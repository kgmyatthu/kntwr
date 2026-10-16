#pragma once
#include <stdint.h>
#define NTW2_FIRE_WORD_LABELS \
 "version", "enabled", "calls", "compared", "mismatches", "faults", "reentry", "needs_owner", \
 "candidate_owner", "request_owner", "gather_owner", "holder_owner", "commit_owner", "gathers_actual", "gathers_predicted", "event_mismatches", \
 "first_entity", "first_offset", "first_expected", "first_actual", "state_before", "state_after", "request_actual", "event_unpredicted"
#define NTW2_FIRE_COMMIT_LABELS \
 "version", "refusals", "primary_observer", "primary_unlink", "primary_other", "multiple_guard_classes", \
 "has_observer_guard", "has_unlink_guard", "has_other_guard", "missing_observer", "missing_speed", \
 "getter_mismatch", "selector_mismatch", "old_remove_mismatch", "new_add_mismatch", \
 "last_entity", "last_mask", "last_flags", "last_observer_vtable", "last_getter", "last_selector", \
 "last_old_observer", "last_old_remove", "last_new_add", "last_list", "last_prev", "last_next", "last_head", \
 "unlink_has_prev", "unlink_has_next", "unlink_is_head", "last_state"
#ifdef __cplusplus
namespace ntw2_sweep { struct WorkerScene; }
namespace ntw2_fire {
using U = uint32_t;
constexpr U SoldierBytes = 0x680;
enum Word : U { Version, Enabled, Calls, Compared, Mismatches, Faults, Reentry, OwnerRequired,
 CandidateOwner, RequestOwner, GatherOwner, HolderOwner, CommitOwner, GathersActual, GathersPredicted, EventMismatches,
 FirstEntity, FirstOffset, FirstExpected, FirstActual, StateBefore, StateAfter, RequestsActual, EventUnpredicted, WordCount };
enum CommitWord : U { CommitVersion, CommitRefusals, CommitPrimaryObserver, CommitPrimaryUnlink, CommitPrimaryOther,
 CommitMultiple, CommitHasObserver, CommitHasUnlink, CommitHasOther, CommitMissingObserver, CommitMissingSpeed,
 CommitGetterMismatch, CommitSelectorMismatch, CommitOldRemoveMismatch, CommitNewAddMismatch,
 CommitLastEntity, CommitLastMask, CommitLastFlags, CommitLastObserver, CommitLastGetter, CommitLastSelector,
 CommitLastOld, CommitLastOldRemove, CommitLastNewAdd, CommitLastList, CommitLastPrev, CommitLastNext, CommitLastHead,
 CommitUnlinkPrev, CommitUnlinkNext, CommitUnlinkHead, CommitLastState, CommitWordCount };
enum CommitGuard : U { GuardObserver = 1, GuardSpeed = 2, GuardGetter = 4, GuardSelector = 8,
 GuardOldRemove = 16, GuardNewAdd = 32, GuardUnlink = 64, GuardUnavailable = 128 };
// Historical namespace only: 659600 is a path/obstacle sequence, not a proved
// weapon-fire sequence. 15AFE0C is temporary gather storage, not an event queue.
enum class Refusal : U { None, Candidate, Request, Gather, Holder, Commit };
// Observational call prediction only, never a replay payload. A refused
// request/gather executes the untouched original on the owner.
enum class EventKind : U { None, PathRequest = 0x8021E0, Gather = 0x80BF70 };
struct Event { EventKind kind = EventKind::None; U receiver = 0; };
struct Binding { U image_delta; bool enabled; };
struct Snapshot {
 U identity = 0;
 alignas(16) uint8_t soldier[SoldierBytes]{};
 float tick_step = 0, sample_scale = 0;
 bool holder_changed = false, holder_valid = false;
 bool pending_valid = false, pending_done = false, pending_ok = false;
 bool descriptor_valid = false;
 U descriptor_target = 0, holder_target = 0;
 // Borrow the mover's generation-frozen environment grid; never recapture it.
 const ntw2_sweep::WorkerScene* environment = nullptr;
 // Caller retains the same immutable scene generation until Run completes.
 bool terrain_known = false, terrain_blocked = false, candidate_target_valid = false;
 float candidate_time = 0, candidate_target[2]{};
 bool commit_valid = false, commit_clear_latches = false;
 U commit_observer = 0;
 float commit_target[2]{}, commit_limit = 0, descriptor_tolerance = 0;
 U commit_guard = GuardUnavailable;
 // Raw call-site witnesses, in CommitLastObserver..CommitLastHead order.
 U commit_witness[10]{};
};
struct Work {
 alignas(16) uint8_t soldier[SoldierBytes]{};
 Refusal refusal = Refusal::None;
 Event event{};
 bool event_known = false;
};
// Capture owner-side only. Run uses only the snapshot and participant-private
// Work, allocates nothing and makes no original calls. On refusal Work is NOT
// committable: replay the untouched original on the owner instead.
bool Capture(U soldier, Snapshot&, const ntw2_sweep::WorkerScene* = nullptr);
bool Run(const Snapshot&, Work&);
bool Start(const Binding&);
void Stop();
void Sample(U* words);
void SampleCommit(U* words);
void ShadowBefore(U soldier);
void ObserveGather(U receiver, const U* args);
void ObserveRequest(U receiver);
void ShadowAfter();
void Abandon();
static_assert(WordCount == 24, "sequence diagnostics are append-only");
static_assert(CommitWordCount == 32, "commit guard diagnostics are append-only");
}
#endif
