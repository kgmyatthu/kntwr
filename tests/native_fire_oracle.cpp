// Historical FIRE name; compare the recovered 659600 path/obstacle sequencer.
// Original instructions are never patched. Refused shared paths are NOT run as
// worker code and are tested separately from the mapped-original closed paths.
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <xmmintrin.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "native_image_relocation.h"
#include "native_fire.h"
#include "../src/loco/native_sweep.h"
namespace port = ntw2_fire;
using U = uint32_t;
using B = uint8_t;
static B* image;
static U delta, cases, checks;
static void Check(bool value, const char* message) {
 ++checks;
 if (!value) { std::fprintf(stderr, "FAIL fire sequence case=%u: %s\n", cases, message); std::exit(1); }
}
static U A(const void* p) { return static_cast<U>(reinterpret_cast<uintptr_t>(p)); }
template<class T> static void Put(void* p, U offset, T value) { std::memcpy(static_cast<B*>(p) + offset, &value, sizeof(value)); }
static B* At(U va) { return reinterpret_cast<B*>(va + delta); }
static void Map(const char* path) {
 FILE* f = std::fopen(path, "rb"); Check(f != nullptr, "open supported executable read-only");
 Check(!std::fseek(f, 0, SEEK_END), "seek"); const long size = std::ftell(f); std::rewind(f);
 Check(size > 0 && size < 256 * 1024 * 1024, "bounded image size");
 std::vector<B> bytes(static_cast<size_t>(size));
 Check(std::fread(bytes.data(), 1, bytes.size(), f) == bytes.size(), "read executable"); std::fclose(f);
 BCRYPT_ALG_HANDLE alg = nullptr; B hash[32];
 Check(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "hash provider");
 Check(BCryptHash(alg, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), hash, 32) == 0, "hash image");
 BCryptCloseAlgorithmProvider(alg, 0);
 char hex[65]; for (U i = 0; i < 32; ++i) std::snprintf(hex + i * 2, 3, "%02x", hash[i]);
 Check(!std::strcmp(hex, "13fcab6298cd5e0072b3598a83cf02627c58f944edbee5258b637655c82cbad4"), "pinned executable SHA256");
 const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
 const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
 Check(nt->OptionalHeader.ImageBase == 0x400000, "preferred base");
 image = static_cast<B*>(VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
 Check(image != nullptr, "private image mapping"); delta = A(image) - 0x400000;
 std::memcpy(image, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
 const auto* sections = IMAGE_FIRST_SECTION(nt);
 for (U i = 0; i < nt->FileHeader.NumberOfSections; ++i)
  std::memcpy(image + sections[i].VirtualAddress, bytes.data() + sections[i].PointerToRawData,
   std::min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize));
 Check(RelocateNativeImage(image, nt->OptionalHeader.SizeOfImage,
  reinterpret_cast<IMAGE_NT_HEADERS32*>(image + dos->e_lfanew), delta), "relocate original image");
 port::Start({delta, true});
}
static void Fp(U mode) {
 unsigned short control = static_cast<unsigned short>(0x27F | (mode << 10));
 __asm fninit
 __asm fldcw control
 _mm_setcsr(0x1F80 | (mode << 13));
}
struct Fixture {
 std::array<B, port::SoldierBytes> soldier{};
 std::array<B, 0x100> root{}, model{}, terrain{}, pending{}, descriptor{}, node{}, payload{};
 std::array<B, 0x100> watched{};
 std::array<U, 16> cells{};
 Fixture(U state) {
  Put(soldier.data(), 0x28, A(root.data())); Put(root.data(), 8, A(model.data()));
  Put(model.data(), 0xA0, A(terrain.data())); Put(model.data(), 0x58, U(100));
  Put(model.data(), 0x84, -100.0f); Put(model.data(), 0x88, -100.0f);
  Put(model.data(), 0x8C, 100.0f); Put(model.data(), 0x90, 100.0f);
  Put(terrain.data(), 0, A(cells.data())); Put(terrain.data(), 8, U(2));
  Put(terrain.data(), 0x14, U(3)); Put(terrain.data(), 0x24, 0.25f);
  Put(soldier.data(), 0x390, state); Put(soldier.data(), 0x39C, A(pending.data()));
  Put(soldier.data(), 0x1C4, U(9)); Put(soldier.data(), 0x43C, 0.75f);
  Put(soldier.data(), 0x148, 1.0f); Put(soldier.data(), 0x14C, 1.0f);
  Put(soldier.data(), 0x4F4, 2.0f);
  Put(At(0x176CFF8), 0, 1.0f); Put(At(0x176CFFC), 0, 0.0f);
 }
};
static void Original(B* soldier) {
 reinterpret_cast<void (__thiscall*)(void*)>(At(0x659600))(soldier);
}
static void Compare(Fixture& f, U rounding) {
 ++cases;
 const auto before = f.soldier;
 const auto world = f.model; const auto terrain = f.cells; const auto watched = f.watched;
 port::Snapshot snapshot; port::Work work;
 Fp(rounding); Check(port::Capture(A(f.soldier.data()), snapshot), "capture closed snapshot");
 Fp(rounding); Check(port::Run(snapshot, work), "closed branch admitted");
 Fp(rounding); Original(f.soldier.data());
 Check(!std::memcmp(f.soldier.data(), work.soldier, port::SoldierBytes), "full soldier output equals untouched original");
 Check(world == f.model && terrain == f.cells && watched == f.watched, "original leaves shared inputs unchanged");
 Check(work.event_known && work.event.kind == port::EventKind::None, "closed branch predicts no shared event");
 f.soldier = before; Fp(rounding); port::ShadowBefore(A(f.soldier.data()));
 Original(f.soldier.data()); port::ShadowAfter();
 U words[port::WordCount]; port::Sample(words);
 Check(words[port::Compared] == cases && words[port::Mismatches] == 0 && words[port::EventMismatches] == 0,
  "shadow accounting matches real original");
}
static void ClosedCases() {
 for (U rounding = 0; rounding != 4; ++rounding) {
  for (U state : {0u, 2u, 4u, 5u, 6u, 7u, 99u}) {
   Fixture f(state); Compare(f, rounding);
  }
  for (U state : {4u, 5u}) {
   Fixture zeroSamples(state); Put(zeroSamples.soldier.data(), 0x4F4, 0.0f); Compare(zeroSamples, rounding);
   Fixture clearTerrain(state); Put(clearTerrain.soldier.data(), 0x4F4, 0.0f);
   Put(clearTerrain.soldier.data(), 0x4F0, 8.0f); Compare(clearTerrain, rounding);
   Fixture cooldown(state); Put(cooldown.soldier.data(), 0x4F4, 0.0f);
   Put(cooldown.soldier.data(), 0x4F0, 8.0f); Put(cooldown.soldier.data(), 0x5D4, 100.0f);
   cooldown.cells.fill(0x100); Compare(cooldown, rounding);
   Fixture zeroDistance(state); Put(zeroDistance.soldier.data(), 0x4F4, 0.0f);
   Put(zeroDistance.soldier.data(), 0x4F0, 8.0f); zeroDistance.cells.fill(0x100); Compare(zeroDistance, rounding);
   Fixture matchingWatch(state); Put(matchingWatch.soldier.data(), 0x3BC, U(1));
   Put(matchingWatch.soldier.data(), 0x3AC, A(matchingWatch.watched.data()));
   Put(matchingWatch.soldier.data(), 0x3E0, U(1)); Put(matchingWatch.soldier.data(), 0x3D0, U(123));
   Put(matchingWatch.watched.data(), 0x88, U(123)); Compare(matchingWatch, rounding);
  }
  for (U state : {3u, 4u, 5u}) {
   Fixture descriptor(state); Put(descriptor.soldier.data(), 0x18, A(descriptor.descriptor.data()));
   Put(descriptor.descriptor.data(), 0x20, U(42)); Put(descriptor.soldier.data(), 0x3A0, A(descriptor.node.data()));
   Put(descriptor.node.data(), 8, A(descriptor.payload.data())); Put(descriptor.payload.data(), 0xC, U(42));
   Compare(descriptor, rounding);
  }
 }
}
static void SetupCommit(Fixture& f, U flags) {
 Put(f.soldier.data(), 0x414, B(1));
 Put(f.soldier.data(), 0xF4, A(At(0x13338C4)));
 Put(f.soldier.data(), 0xF8, A(At(0x1454168)));
 Put(f.soldier.data(), 0x1E8, A(f.payload.data()));
 Put(f.payload.data(), 0x20, 3.75f);
 Put(f.soldier.data(), 0x438, flags);
 Put(f.soldier.data(), 0x40C, 1.25f); Put(f.soldier.data(), 0x410, 2.375f);
 Put(f.soldier.data(), 0x3F4, 3.25f); Put(f.soldier.data(), 0x3FC, -4.125f);
 Put(f.soldier.data(), 0x424, 9.5f); Put(f.soldier.data(), 0x42C, -7.0f);
 Put(f.soldier.data(), 0x108, U(123)); Put(f.soldier.data(), 0x188, U(456));
 Put(f.soldier.data(), 0x134, U(789)); Put(f.soldier.data(), 0x13C, B(1));
 Put(f.soldier.data(), 0x1A8, B(1));
}
static void CommitCases() {
 for (U rounding = 0; rounding != 4; ++rounding)
  for (U state : {4u, 5u})
   for (U flags : {1u, 0x18u, 0x118u, 0x218u, 0x405u})
    for (U variant = 0; variant != 4; ++variant) {
     Fixture f(state); SetupCommit(f, flags);
     if (variant == 1) {
      std::memcpy(f.soldier.data() + 0x160, f.soldier.data() + 0x424, 20);
      Put(f.soldier.data(), 0xF8, U(0));
     } else if (variant == 2) {
      Put(f.soldier.data(), 0x410, -1.0f);
     } else if (variant == 3) {
      Put(f.soldier.data(), 0x40C, 100.0f);
      // A nonnull membership is safe ONLY when flags&4 suppress unlink.
      if (flags & 4) Put(f.soldier.data(), 0x178, A(f.node.data()));
     }
     Compare(f, rounding);
    }
 // Real shared unlink and unknown observer callbacks must still refuse.
 Fixture linked(4); SetupCommit(linked, 1); Put(linked.soldier.data(), 0x178, A(linked.node.data()));
 port::Snapshot s; port::Work w;
 Check(port::Capture(A(linked.soldier.data()), s) && !port::Run(s, w) &&
  w.refusal == port::Refusal::Commit, "foreign linked-list unlink remains owner-only");
 Fixture observer(4); SetupCommit(observer, 1);
 Put(observer.soldier.data(), 0xF8, A(observer.node.data()));
 Put(observer.node.data(), 0, A(At(0x13338C4)));
 Check(port::Capture(A(observer.soldier.data()), s) && !port::Run(s, w),
  "unclassified previous observer transition remains owner-only");
 Fixture completed(2); Put(completed.pending.data(), 0x20, B(1)); Put(completed.pending.data(), 0x21, B(1));
 Put(completed.soldier.data(), 0x3A4, B(1));
 Check(port::Capture(A(completed.soldier.data()), s) && !port::Run(s, w) &&
  w.refusal == port::Refusal::Holder && w.event_known && w.event.kind == port::EventKind::Gather,
  "completed request predicts gather after 8121C0 clears holder latch");
}
static void ObserverRemovalCases() {
 for (U rounding = 0; rounding != 4; ++rounding)
  for (U state : {4u, 5u})
   for (U flags : {0x11u, 0x111u})
    for (U oldObserver : {0x1454168u, 0x145416Cu}) {
     Fixture f(state); SetupCommit(f, flags);
     Put(f.soldier.data(), 0xF8, A(At(oldObserver)));
     // The real removal clears exactly 114/115/119, not adjacent bytes.
     Put(f.soldier.data(), 0x114, U(0xA7B6C5D4));
     Put(f.soldier.data(), 0x118, B(0x2B)); Put(f.soldier.data(), 0x119, B(0x5A));
     Put(f.soldier.data(), 0x11A, B(0x7F));
     std::array<B, 32> observers; std::memcpy(observers.data(), At(0x1454168), observers.size());
     Compare(f, rounding);
     const bool cleared = oldObserver == 0x145416C;
     Check(f.soldier[0x114] == (cleared ? 0 : 0xD4) && f.soldier[0x115] == (cleared ? 0 : 0xC5) &&
      f.soldier[0x119] == (cleared ? 0 : 0x5A), "real observer removal clears only recovered soldier latches");
     Check(f.soldier[0x116] == 0xB6 && f.soldier[0x117] == 0xA7 &&
      f.soldier[0x118] == 0x2B && f.soldier[0x11A] == 0x7F, "neighboring participant bytes preserved");
     Check(!std::memcmp(observers.data(), At(0x1454168), observers.size()),
      "old and new observer singleton objects remain byte-identical");
    }
}
static void RefusalCases() {
 // These assertions test pre-side-effect refusal, not fabricated native events.
 for (U state : {1u, 3u, 4u}) {
  Fixture f(state);
  if (state == 4) Put(f.soldier.data(), 0x414, B(1));
  port::Snapshot snapshot; port::Work work;
  Check(port::Capture(A(f.soldier.data()), snapshot), "refusal snapshot");
  const auto before = f.soldier;
  Check(!port::Run(snapshot, work), "shared branch refuses");
  const auto expected = state == 1 ? port::Refusal::Request : state == 3 ? port::Refusal::Gather : port::Refusal::Commit;
  Check(work.refusal == expected && f.soldier == before, "correct reason with untouched live soldier");
  if (state == 3) Check(work.event_known && work.event.kind == port::EventKind::Gather &&
   work.event.receiver == A(f.soldier.data()) + 0x394, "gather call prediction uses holder receiver");
 }
 Fixture changed(4); Put(changed.soldier.data(), 0x3BC, U(1));
 Put(changed.soldier.data(), 0x3AC, A(changed.watched.data())); Put(changed.soldier.data(), 0x3E0, U(1));
 Put(changed.watched.data(), 0x88, U(7));
 port::Snapshot snapshot; port::Work work;
 Check(port::Capture(A(changed.soldier.data()), snapshot) && !port::Run(snapshot, work) &&
  work.refusal == port::Refusal::Request, "watcher invalidation resets sequence before request refusal");
 Fixture obstacle(4); Put(obstacle.soldier.data(), 0x4F4, 0.0f); Put(obstacle.soldier.data(), 0x4F0, 8.0f);
 Put(obstacle.soldier.data(), 0x424, 10.0f); obstacle.cells.fill(0x100);
 ntw2_sweep::WorkerScene environment; environment.built = true; environment.topology.type.push_back(0x800);
 environment.model = A(obstacle.model.data());
 Check(port::Capture(A(obstacle.soldier.data()), snapshot, &environment) && !port::Run(snapshot, work) &&
  work.refusal == port::Refusal::Candidate, "borrowed environment preserves obstacle narrow-phase refusal");
 environment.topology.type.clear();
 Check(port::Run(snapshot, work), "empty verified environment cannot supply an obstacle hit");
 environment.model = 0;
 Check(port::Capture(A(obstacle.soldier.data()), snapshot, &environment) && !port::Run(snapshot, work),
  "foreign model snapshot is not admitted");
 // Reentry must not prematurely consume the outer shadow frame.
 Fixture nested(0); port::ShadowBefore(A(nested.soldier.data())); port::ShadowBefore(A(nested.soldier.data()));
 port::ShadowAfter(); Original(nested.soldier.data()); port::ShadowAfter();
 U words[port::WordCount]; port::Sample(words);
 Check(words[port::Reentry] == 1 && words[port::Compared] == cases, "nested shadow refuses outer comparison");
 Check(words[port::Faults] == 0 && words[port::Mismatches] == 0, "no faults or mismatches");
 port::Abandon(); port::Stop();
}
static U ReadWord(const void* p, U offset) { U v; std::memcpy(&v, static_cast<const B*>(p) + offset, 4); return v; }
static void CommitDiagnosticCases() {
 port::Start({delta, true});
 const U masks[] = {port::GuardObserver, port::GuardSpeed, port::GuardGetter, port::GuardSelector,
  port::GuardOldRemove, port::GuardNewAdd, port::GuardUnlink,
  port::GuardGetter | port::GuardSpeed | port::GuardUnlink};
 for (U mask : masks) {
  Fixture f(4); SetupCommit(f, 1);
  std::array<U, 4> observerMethods{}; std::memcpy(observerMethods.data(), At(0x13338C4), 16);
  Put(f.soldier.data(), 0xF4, A(observerMethods.data()));
  std::array<U, 5> addMethods{};
  const U originalAddVtable = ReadWord(At(0x1454168), 0);
  std::memcpy(addMethods.data(), reinterpret_cast<const void*>(originalAddVtable), sizeof(addMethods));
  if (mask & port::GuardObserver) Put(f.soldier.data(), 0xF4, U(0));
  if (mask & port::GuardSpeed) Put(f.soldier.data(), 0x1E8, U(0));
  if (mask & port::GuardGetter) observerMethods[1] = A(At(0x444B60));
  if (mask & port::GuardSelector) observerMethods[3] = A(At(0x444B60));
  if (mask & port::GuardOldRemove) {
   Put(f.node.data(), 0, A(observerMethods.data()));
   Put(f.soldier.data(), 0xF8, A(f.node.data()));
  }
  if (mask & port::GuardNewAdd) {
   addMethods[1] = A(At(0x444B60));
   Put(At(0x1454168), 0, A(addMethods.data())); // Data-only fixture, no instruction changes.
  }
  if (mask & port::GuardUnlink) {
   Put(f.soldier.data(), 0x178, A(f.node.data())); Put(f.node.data(), 4, A(f.soldier.data()));
   Put(f.soldier.data(), 0x17C, A(f.watched.data())); Put(f.soldier.data(), 0x180, A(f.payload.data()));
  }
  port::Snapshot snapshot; port::Work work;
  Check(port::Capture(A(f.soldier.data()), snapshot) && snapshot.commit_guard == mask,
   "every commit guard is captured independently, including overlaps");
  Check(!port::Run(snapshot, work) && work.refusal == port::Refusal::Commit, "diagnostic guard still refuses");
  port::ShadowBefore(A(f.soldier.data())); port::Abandon();
  U words[port::CommitWordCount]; port::SampleCommit(words);
  Check(words[port::CommitLastMask] == mask && words[port::CommitLastEntity] == A(f.soldier.data()),
   "commit mask and participant witness exported");
  Put(At(0x1454168), 0, originalAddVtable);
 }
 U d[port::CommitWordCount]; port::SampleCommit(d);
 Check(d[port::CommitRefusals] == 8 && d[port::CommitPrimaryObserver] == 6 &&
  d[port::CommitPrimaryUnlink] == 1 && d[port::CommitPrimaryOther] == 1,
  "exclusive primary reasons exactly partition commit refusals");
 Check(d[port::CommitHasObserver] == 6 && d[port::CommitHasUnlink] == 2 &&
  d[port::CommitHasOther] == 2 && d[port::CommitMultiple] == 1, "overlap counters retain all failed classes");
 Check(d[port::CommitUnlinkPrev] == 2 && d[port::CommitUnlinkNext] == 2 &&
  d[port::CommitUnlinkHead] == 2, "shared-list witnesses recorded");
 port::Start({delta, true}); port::SampleCommit(d);
 Check(d[port::CommitVersion] == 1 && d[port::CommitRefusals] == 0 && d[port::CommitLastMask] == 0,
  "commit diagnostics reset on activation");
 port::Stop();
}
static void SharedMembershipOracle() {
 // Execute real enrollment/unlink bodies. Membership belongs to a controller
 // header, while intrusive links live in MULTIPLE distinct soldiers.
 Fixture a(0), b(0), c(0);
 std::array<U, 2> list{};
 auto enroll = reinterpret_cast<void (__thiscall*)(void*, void*)>(At(0x7EE850));
 auto unlink = reinterpret_cast<void (__thiscall*)(void*, void*)>(At(0x811C60));
 enroll(list.data(), a.soldier.data()); enroll(list.data(), b.soldier.data()); enroll(list.data(), c.soldier.data());
 Check(list[1] == A(c.soldier.data()) && ReadWord(a.soldier.data(), 0x17C) == A(b.soldier.data()),
  "original enrollment creates a multi-soldier intrusive list");
 unlink(list.data(), b.soldier.data());
 Check(ReadWord(c.soldier.data(), 0x180) == A(a.soldier.data()) &&
  ReadWord(a.soldier.data(), 0x17C) == A(c.soldier.data()), "middle unlink writes two foreign participants");
 Check(ReadWord(b.soldier.data(), 0x178) == 0 && ReadWord(b.soldier.data(), 0x184) == 2,
  "middle unlink also clears own membership");
 unlink(list.data(), c.soldier.data());
 Check(list[1] == A(a.soldier.data()) && ReadWord(a.soldier.data(), 0x17C) == 0,
  "head unlink writes shared controller head and foreign next participant");
 unlink(list.data(), a.soldier.data());
 Check(list[1] == 0, "singleton unlink still mutates foreign controller header");
}
int main(int argc, char** argv) {
 if (argc != 2) { std::fprintf(stderr, "usage: native_fire_oracle Napoleon.exe\n"); return 2; }
 Map(argv[1]); ClosedCases(); CommitCases(); ObserverRemovalCases(); RefusalCases(); CommitDiagnosticCases(); SharedMembershipOracle();
 std::printf("PASS sequence mapped-original oracle cases=%u checks=%u; shared branches refused, not replayed\n", cases, checks);
 VirtualFree(image, 0, MEM_RELEASE); return 0;
}
