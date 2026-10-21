#include <windows.h>
#include <xmmintrin.h>
#include <intrin.h>
#include <string.h>
#include "native_fire.h"
#include "loco/native_sweep.h"

static_assert(sizeof(void*) == 4, "sequence port requires the pinned x86 ABI");
namespace kntwr_fire {
namespace {
U delta, words[WordCount], commitWords[CommitWordCount];
bool enabled, active;
U nesting, actualGather, actualRequest, actualReceiver;
Snapshot shadow;
Work predicted;
U D(U a) { return *reinterpret_cast<const U*>(a); }
uint8_t B(U a) { return *reinterpret_cast<const uint8_t*>(a); }
float F(U a) { return *reinterpret_cast<const float*>(a); }
U Get(const uint8_t* p, U o) { U v; memcpy(&v, p + o, 4); return v; }
float Float(const uint8_t* p, U o) { float v; memcpy(&v, p + o, 4); return v; }
void Put(uint8_t* p, U o, U v) { memcpy(p + o, &v, 4); }
float Add(float a, float b) { return _mm_cvtss_f32(_mm_add_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Mul(float a, float b) { return _mm_cvtss_f32(_mm_mul_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float Sub(float a, float b) { return _mm_cvtss_f32(_mm_sub_ss(_mm_set_ss(a), _mm_set_ss(b))); }
bool Above(float a, float b) { return _mm_comigt_ss(_mm_set_ss(a), _mm_set_ss(b)) != 0; }
float Div(float a, float b) { return _mm_cvtss_f32(_mm_div_ss(_mm_set_ss(a), _mm_set_ss(b))); }
float X87Product(float a, float b) {
 float result;
 __asm { fld a }
 __asm { fmul b }
 __asm { fstp result }
 return result;
}
// Preserve the original x87 rounding-control-sensitive doubled-coordinate
// conversion (7F1587/7F15B6), including unsigned clamp after adding bias.
U Cell(float scaled, U bias, U upper) {
 int v;
 const float half = -0.5f;
 __asm {
  fld scaled
  fadd st(0), st(0)
  fadd half
  fistp v
 }
 const U index = static_cast<U>(v >> 1) + bias;
 return index > upper ? upper : index;
}
// 7F14C0: read-only terrain occupancy lookahead, not a weapon predicate.
// Owner snapshot capture samples live terrain under the site's serial barrier;
// no terrain address or native call escapes into Run.
bool TerrainProbe(U soldier, float scale, bool& blocked) {
 const int count = _mm_cvtt_ss2si(_mm_set_ss(Mul(F(soldier + 0x4F0), scale)));
 blocked = false;
 if (!count) return true;
 // Negative/indefinite conversion would mean billions of unsigned iterations.
 // Preserve owner behavior by refusing, never truncate the original loop.
 if (count < 0) return false;
 const U model = D(D(soldier + 0x28) + 8), terrain = D(model + 0xA0);
 const U angle = *reinterpret_cast<const uint16_t*>(soldier + 0x64);
 const float dx = F(delta + 0x176CFF8 + angle * 8), dz = F(delta + 0x176CFFC + angle * 8);
 const float step = F(delta + 0x1325D20);
 float distance = step;
 for (int n = 0; n != count; ++n, distance = Add(distance, step)) {
  const float x = Add(Mul(dx, distance), F(soldier + 0x48));
  const float z = Add(Mul(dz, distance), F(soldier + 0x50));
  // Original JB treats unordered as outside; JBE upper bounds do likewise.
  if (!(x >= F(model + 0x84)) || !(z >= F(model + 0x88)) ||
      !Above(F(model + 0x8C), x) || !Above(F(model + 0x90), z)) continue;
  const U ix = Cell(Mul(x, F(terrain + 0x24)), D(terrain + 0x10), D(terrain + 0x14));
  const U iz = Cell(Mul(z, F(terrain + 0x24)), D(terrain + 0x10), D(terrain + 0x14));
  if (D(D(terrain) + 4 * (ix + (iz << (D(terrain + 8) & 31)))) & 0x100) {
   blocked = true; return true;
  }
 }
 return true;
}
void Position(U descriptor, float out[2]) {
 const U transform = D(descriptor + 0x10);
 if (!transform) { out[0] = F(descriptor); out[1] = F(descriptor + 8); return; }
 const float x = F(descriptor), y = F(descriptor + 4), z = F(descriptor + 8);
 out[0] = Add(Add(Add(Mul(F(transform + 0xA0), y), Mul(F(transform + 0x9C), x)), Mul(F(transform + 0xA4), z)), F(transform + 0x80));
 out[1] = Add(Add(Add(Mul(F(transform + 0xB8), y), Mul(F(transform + 0xB4), x)), Mul(F(transform + 0xBC), z)), F(transform + 0x88));
}
void CaptureBody(U soldier, Snapshot& s, const kntwr_sweep::WorkerScene* environment) {
 s = Snapshot{}; s.identity = soldier;
 memcpy(s.soldier, reinterpret_cast<const void*>(soldier), SoldierBytes);
 s.tick_step = F(delta + 0x131A7B0);
 s.sample_scale = F(delta + 0x1325CAC);
 const U holder = soldier + 0x394;
 const U inlineCount = D(holder + 0x28), spillCount = D(holder + 0x34), labels = D(holder + 0x4C);
 // Exact unsigned sum/ordering of 807490. Each foreign +88 is snapshotted
 // before Run; labels may change in site 6, so this is NOT a static scene read.
 const U total = inlineCount + spillCount;
 for (U i = 0; i < total; ++i) {
  const U subject = i < inlineCount ? D(holder + 0x18 + 4 * i) : D(D(holder + 0x38) + 4 * (i - inlineCount));
  const U label = i < labels ? D(holder + 0x3C + 4 * i) : D(D(holder + 0x5C) + 4 * (i - labels));
  if (D(subject + 0x88) != label) { s.holder_changed = true; break; }
 }
 s.holder_valid = true;
 const U state = D(soldier + 0x390);
 if (state == 2) {
  const U pending = D(soldier + 0x39C);
  if (pending) { s.pending_valid = true; s.pending_done = B(pending + 0x20) == 1; s.pending_ok = B(pending + 0x21) == 1; }
 }
 if (state >= 3 && state <= 5 && D(soldier + 0x18)) {
  s.descriptor_valid = true; s.descriptor_target = D(D(soldier + 0x18) + 0x20);
  const U node = D(holder + 0xC);
  s.holder_target = node ? D(D(node + 8) + 0xC) : 0;
 }
 if ((state == 4 || state == 5) && !D(soldier + 0x18) &&
     !D(soldier + 0x3A8) && B(soldier + 0x414) == 1 &&
     ((D(soldier + 0x438) & 1) || !B(soldier + 0x440))) {
  const U observer = D(soldier + 0xF4), old = D(soldier + 0xF8);
  const U newObserver = delta + 0x1454168, speed = D(soldier + 0x1E8);
  const U getter = observer ? D(observer + 4) : 0, selector = observer ? D(observer + 0xC) : 0;
  const U oldRemove = old ? D(D(old) + 0xC) : 0, newAdd = D(D(newObserver) + 4);
  const U list = D(soldier + 0x178), flags = D(soldier + 0x438);
  s.commit_guard = (!observer ? GuardObserver : 0u) | (!speed ? GuardSpeed : 0u) |
      (observer && getter != delta + 0x5562A0 ? GuardGetter : 0u) |
      (observer && selector != delta + 0x5D6F60 ? GuardSelector : 0u) |
      (old && oldRemove != delta + 0x44A780 && oldRemove != delta + 0x7DE1E0 ? GuardOldRemove : 0u) |
      (newAdd != delta + 0x7DE0B0 ? GuardNewAdd : 0u) |
      (list && !(flags & 4) ? GuardUnlink : 0u);
  const U witness[10] = {observer, getter, selector, old, oldRemove, newAdd, list,
      D(soldier + 0x17C), D(soldier + 0x180), list ? D(list + 4) : 0};
  memcpy(s.commit_witness, witness, sizeof(witness));
  s.commit_clear_latches = old && oldRemove == delta + 0x7DE1E0;
  // Diagnose every guard, including overlaps. Never turn an unknown observer
  // callback or linked-list mutation into a no-op to improve admission.
  if (!s.commit_guard) {
   Position(soldier + 0x3F4, s.commit_target);
   s.commit_limit = X87Product(F(speed + 0x20), F(delta + 0x1335A24));
   s.descriptor_tolerance = F(delta + 0x1318034);
   s.commit_observer = newObserver; s.commit_valid = true;
  }
 }
 if (state != 4 && state != 5) return;
 const float threshold = F(soldier + 0x4F4);
 if (Above(threshold, F(soldier + 0x148)) || Above(threshold, F(soldier + 0x14C))) return;
 s.terrain_known = TerrainProbe(soldier, s.sample_scale, s.terrain_blocked);
 if (!s.terrain_known || !s.terrain_blocked) return;
 const U model = D(D(soldier + 0x28) + 8);
 if (environment && environment->built && environment->model == model)
  s.environment = environment;
 // Original converts unsigned tick through double, then rounds to float.
 s.candidate_time = Mul(static_cast<float>(static_cast<double>(D(model + 0x58))), s.tick_step);
 if (Above(F(soldier + 0x5D4), s.candidate_time)) return;
 Position(soldier + 0x424, s.candidate_target); s.candidate_target_valid = true;
}
bool Refuse(Work& w, Refusal reason, EventKind event = EventKind::None, U receiver = 0) {
 w.refusal = reason; w.event = {event, receiver};
 w.event_known = event == EventKind::Gather;
 return false;
}
bool Candidate(const Snapshot& s, Work& w) {
 const uint8_t* p = s.soldier;
 const float threshold = Float(p, 0x4F4);
 if (Above(threshold, Float(p, 0x148)) || Above(threshold, Float(p, 0x14C))) {
  Put(w.soldier, 0x1C4, 1); return true;
 }
 if (!s.terrain_known) return Refuse(w, Refusal::Candidate);
 if (!s.terrain_blocked) { Put(w.soldier, 0x1C4, 1); return true; }
 if (Above(Float(p, 0x5D4), s.candidate_time)) return true;
 if (!s.candidate_target_valid) return Refuse(w, Refusal::Candidate);
 const float dx = Sub(s.candidate_target[0], Float(p, 0x48));
 const float dz = Sub(s.candidate_target[1], Float(p, 0x50));
 if (!Above(Add(Mul(dx, dx), Mul(dz, dz)), 0.0f)) return true;
 // Reuse the mover's verified static environment snapshot. If it has no 800
 // nodes, 62EB73's grid walk cannot find a hit. Nonempty obstacle geometry
 // requires 559C10 + animation selection and remains explicitly owner-only.
 if (!s.environment || !s.environment->built) return Refuse(w, Refusal::Candidate);
 for (U type : s.environment->topology.type)
  if (type == 0x800) return Refuse(w, Refusal::Candidate);
 Put(w.soldier, 0x1C4, 1); return true;
}
bool Commit(const Snapshot& s, Work& w) {
 if (!s.commit_valid) return Refuse(w, Refusal::Commit);
 uint8_t* p = w.soldier;
 const U flags = Get(p, 0x438);
 const bool latch = !(flags & 1);
 const float dx = Sub(Float(p, 0x48), s.commit_target[0]);
 const float dz = Sub(Float(p, 0x50), s.commit_target[1]);
 const float distance = _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(Add(Mul(dx, dx), Mul(dz, dz)))));
 const float time = Sub(Float(p, 0x410), Float(p, 0x43C));
 float speed = Float(p, 0x40C);
 // 63F040 returns descriptor speed * scale through x87; 63AF40 performs
 // the exact SSE arrival-speed clamp. MIN/MAX operand order matters for NaN.
 if (Above(time, 0.0f)) {
  float remaining = Sub(distance, Mul(speed, time));
  if (latch) remaining = _mm_cvtss_f32(_mm_max_ss(_mm_set_ss(remaining), _mm_setzero_ps()));
  const float arriving = Add(Div(remaining, time), speed);
  speed = Above(s.commit_limit, arriving) ? arriving : s.commit_limit;
 }
 if (latch) p[0x440] = 1;
 bool same = Get(p, 0x434) == Get(p, 0x170) &&
     p[0x430] == p[0x16C] && p[0x431] == p[0x16D];
 for (U i = 0; same && i != 12; i += 4) {
  const float difference = Sub(Float(p, 0x424 + i), Float(p, 0x160 + i));
  U bits; memcpy(&bits, &difference, 4); bits &= 0x7FFFFFFF;
  float magnitude; memcpy(&magnitude, &bits, 4);
  same = magnitude <= s.descriptor_tolerance;
 }
 if ((flags & 0x200) || !same) { p[0x13C] = 0; p[0x1A8] = 0; }
 Put(p, 0x108, 0); memcpy(p + 0x160, p + 0x424, 20);
 memcpy(p + 0x10C, &speed, 4); Put(p, 0x110, flags); Put(p, 0x188, 0);
 // 7DE1E0 -> 806570 receives entity+F4, not the old observer singleton.
 // Its two stores are participant-private; do not replace this with a no-op.
 if (s.commit_clear_latches) { p[0x114] = 0; p[0x115] = 0; p[0x119] = 0; }
 Put(p, 0xF8, s.commit_observer);
 if (flags & 0x100) Put(p, 0x134, 0); // 805AA0 sees ECX = entity+F4.
 return true;
}
void Mismatch(U offset, U expected, U actual) {
 ++words[Mismatches];
 if (!words[FirstEntity]) {
  words[FirstEntity] = shadow.identity; words[FirstOffset] = offset;
  words[FirstExpected] = expected; words[FirstActual] = actual;
 }
}
}
bool Capture(U soldier, Snapshot& s, const kntwr_sweep::WorkerScene* environment) {
 __try { CaptureBody(soldier, s, environment); return true; }
 __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool Run(const Snapshot& s, Work& w) {
 memcpy(w.soldier, s.soldier, SoldierBytes);
 w.refusal = Refusal::None; w.event = Event{}; w.event_known = false;
 if (!s.holder_valid) return Refuse(w, Refusal::Holder);
 uint8_t* p = w.soldier;
 U state = Get(p, 0x390);
 if (state == 4 || state == 5) {
  // 63C4F0 discards Candidate's AL and always returns zero.
  if (!Candidate(s, w)) return false;
  if ((p[0x174] && !p[0x117] && (!p[0x3A4] || !p[0x13C])) || s.holder_changed) {
   state = 1; Put(p, 0x390, 1); Put(p, 0x41C, 0);
  }
 }
 p[0xEF] = Get(p, 0x1C4) != 1;
 if (state == 1) return Refuse(w, Refusal::Request);
 if (state == 2) {
  if (!s.pending_valid || s.pending_done) {
   // 8121C0 installs the completed path head, clears holder+10 (=3A4),
   // then unregisters watchers. The latter remains owner-only, but it cannot
   // hide the ensuing state-3 gather when no descriptor-owner bypass exists.
   if (s.pending_valid && s.pending_done && s.pending_ok && !Get(p, 0x18))
    return Refuse(w, Refusal::Holder, EventKind::Gather, s.identity + 0x394);
   return Refuse(w, Refusal::Holder);
  }
 } else if (state == 3 || state == 4 || state == 5) {
  if (Get(p, 0x18)) {
   if (!s.descriptor_valid) return Refuse(w, Refusal::Holder);
   if (s.holder_target == s.descriptor_target) p[0x1C] = 1;
  } else {
   const bool gatherBranch = state == 3 || (p[0x117] == 1 && Get(p, 0x184) == 2) ||
       (Get(p, 0x3A8) && Get(p, 0x184) == 2);
   if (gatherBranch) {
    if (p[0x3A4] == 1) return Refuse(w, Refusal::Holder);
    return Refuse(w, Refusal::Gather, EventKind::Gather, s.identity + 0x394);
   }
   if (!Get(p, 0x3A8) && (state == 4 || state == 5) && p[0x414] == 1 &&
       ((Get(p, 0x438) & 1) || !p[0x440])) {
    if (!Commit(s, w)) return false;
   }
  }
 }
 const float elapsed = Add(Float(p, 0x43C), s.tick_step);
 memcpy(p + 0x43C, &elapsed, 4);
 w.event_known = true;
 return true;
}
void RecordCommitRefusal(const Snapshot& s) {
 const U mask = s.commit_guard;
 const bool observer = (mask & (GuardObserver | GuardGetter | GuardSelector | GuardOldRemove | GuardNewAdd)) != 0;
 const bool unlink = (mask & GuardUnlink) != 0, other = (mask & (GuardSpeed | GuardUnavailable)) != 0;
 ++commitWords[CommitRefusals];
 ++commitWords[observer ? CommitPrimaryObserver : unlink ? CommitPrimaryUnlink : CommitPrimaryOther];
 commitWords[CommitHasObserver] += observer; commitWords[CommitHasUnlink] += unlink;
 commitWords[CommitHasOther] += other;
 commitWords[CommitMultiple] += static_cast<U>(observer) + unlink + other > 1;
 const U bits[] = {GuardObserver, GuardSpeed, GuardGetter, GuardSelector, GuardOldRemove, GuardNewAdd};
 for (U i = 0; i != 6; ++i) commitWords[CommitMissingObserver + i] += (mask & bits[i]) != 0;
 commitWords[CommitLastEntity] = s.identity; commitWords[CommitLastMask] = mask;
 commitWords[CommitLastFlags] = Get(s.soldier, 0x438);
 memcpy(commitWords + CommitLastObserver, s.commit_witness, sizeof(s.commit_witness));
 if (unlink) {
  commitWords[CommitUnlinkPrev] += s.commit_witness[7] != 0;
  commitWords[CommitUnlinkNext] += s.commit_witness[8] != 0;
  commitWords[CommitUnlinkHead] += s.commit_witness[9] == s.identity;
 }
 commitWords[CommitLastState] = Get(s.soldier, 0x390);
}
bool Start(const Binding& b) {
 delta = b.image_delta; enabled = b.enabled; active = false; nesting = 0;
 memset(words, 0, sizeof(words)); words[Version] = 4; words[Enabled] = enabled;
 memset(commitWords, 0, sizeof(commitWords)); commitWords[CommitVersion] = 1;
 return true;
}
void Stop() { enabled = false; active = false; nesting = 0; words[Enabled] = 0; }
void Sample(U* out) { if (out) memcpy(out, words, sizeof(words)); }
void SampleCommit(U* out) { if (out) memcpy(out, commitWords, sizeof(commitWords)); }
void Abandon() { active = false; nesting = 0; }
void ShadowBefore(U soldier) {
 if (!enabled) return;
 if (active) {
  ++nesting; ++words[Reentry];
  if (predicted.refusal == Refusal::None) { ++words[OwnerRequired]; ++words[HolderOwner]; }
  predicted.refusal = Refusal::Holder; predicted.event_known = false;
  return;
 }
 ++words[Calls];
 alignas(16) uint8_t fp[512];
 _fxsave(fp);
 if (!Capture(soldier, shadow)) { _fxrstor(fp); ++words[Faults]; return; }
 active = true; actualGather = actualRequest = actualReceiver = 0;
 words[StateBefore] = Get(shadow.soldier, 0x390);
 if (!Run(shadow, predicted)) {
  ++words[OwnerRequired];
  ++words[CandidateOwner + static_cast<U>(predicted.refusal) - 1];
  if (predicted.refusal == Refusal::Commit) RecordCommitRefusal(shadow);
 }
 if (predicted.event.kind == EventKind::Gather) ++words[GathersPredicted];
 _fxrstor(fp);
}
void ObserveGather(U receiver, const U*) {
 if (!active) return;
 ++actualGather; actualReceiver = receiver; ++words[GathersActual];
}
void ObserveRequest(U) { if (active) { ++actualRequest; ++words[RequestsActual]; } }
void ShadowAfter() {
 if (!active) return;
 if (nesting) { --nesting; return; }
 __try {
  words[StateAfter] = D(shadow.identity + 0x390);
  if (predicted.event_known) {
   const bool gather = predicted.event.kind == EventKind::Gather;
   if (actualGather != static_cast<U>(gather) || (gather && actualReceiver != predicted.event.receiver) ||
       (predicted.refusal == Refusal::None && actualRequest))
    ++words[EventMismatches];
  } else if (actualGather || actualRequest) ++words[EventUnpredicted];
  if (predicted.refusal == Refusal::None) {
   ++words[Compared];
   // Compare the entire participant prefix, not merely the expected writes.
   const uint8_t* actual = reinterpret_cast<const uint8_t*>(shadow.identity);
   for (U i = 0; i < SoldierBytes; ++i)
    if (predicted.soldier[i] != actual[i]) { Mismatch(i, predicted.soldier[i], actual[i]); break; }
  }
 } __except(EXCEPTION_EXECUTE_HANDLER) { ++words[Faults]; }
 active = false;
}
}
