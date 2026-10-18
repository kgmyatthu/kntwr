#pragma once
#include <stdint.h>
#include "core/native_workload.h"

// Owner-owned lifetime. No original executable instructions are patched.
namespace ntw2_loco { struct GridView; }
namespace ntw2_contact { struct Plan; }
namespace ntw2_collide {
enum Word : uint32_t {
    Calls, SolverTicks, FallbackTicks, CapacityFallbacks, LayoutFallbacks,
    StickyFallbacks, Records, Cells, Pairs, Contacts, Callbacks,
    GatherUs, BinUs, PairsUs, ApplyUs, RebuildUs, StageUs, MaxUs,
    Faults, Rebuilds, Redistributions, LabelChanges, WorkerChunks,
    InlineChunks, MaxPairs, MaxRecords, NodeFallbacks, PoolFallbacks,
    ArenaFallbacks, LastException, OwnerContinuations, EligibleQueries,
    DiagnosticReason, DiagnosticRecord, DiagnosticNode, DiagnosticType,
    DiagnosticVtable, DiagnosticOwner, DiagnosticPayload, DiagnosticId,
    DiagnosticCell, DiagnosticExpectedRecord, NativeQueries, UnsupportedCells,
    ShapedPairs, GatherThreadUs, BinThreadUs, PairsThreadUs, ApplyThreadUs,
    RebuildThreadUs, AuditUs, StoreUs, RedistributeUs, CallbackUs, ReductionUs,
    ThreadClockFailures, StoreThreadUs, RedistributeThreadUs, CallbackThreadUs,
    ReductionThreadUs, AuditThreadUs,
    WordCount
};
enum NodeIssue : uint32_t {
    OwnType=1, OwnId, OwnPayload, OwnOwner, OwnCell, OwnCoverage,
    ChainType, ChainPrevious, ChainCell, ChainOwner, ChainPayload,
    ChainId, ChainArray, ChainCount
};
struct Binding {
    uint32_t image_delta;
    void (__stdcall* dispatch)(uint32_t, uint32_t, uint32_t, void*);
    uint32_t pool;
    uint32_t workers;
    // Optional borrowed owned-grid publication reader (null = native chain audit path).
    // Non-null requests owned mode: the stage consumes the returned CSR directly. A null
    // view, or any identity/geometry mismatch against live state, runs the untouched
    // original stage before the first game write; the grid is never rebuilt or audited here.
    const ntw2_loco::GridView* (*read_grid)(void* manager);
    // ntw2_contact::Mode (0 off): ModeShadow plans every callback on the pool and compares it with
    // the original the owner still runs; ModeWorkers replays planned same-team effects on the owner.
    uint32_t contact_mode;
};
// Separate append-only status block; never extends Word/WordCount.
enum SourceKind : uint32_t { SourceNone, SourceNativeAudit, SourceOwned };
enum SourceWord : uint32_t {
    // SourceKind of the most recent stage (SourceNone when it ran the original stage).
    Source,
    NativeStages,   // completed solver stages built from the native-chain audit
    OwnedStages,    // completed solver stages that borrowed the owned CSR
    OwnedRefusals,  // original-stage fallbacks while owned mode was requested
    SourceWordCount
};
// Resets counters and binds callbacks; no workload storage is reserved.
bool Start(const Binding& binding);
// Exact planned reservation after Start, without allocation; UINT32_MAX for invalid capacity.
uint32_t EstimateActivationBytes(const ntw2_workload::Capacity& capacity);
// Owner-boundary allocation/prefault only. Capacity exhaustion later refuses the whole stage.
bool Activate(void* manager,const ntw2_workload::Capacity& capacity);
uint32_t StorageBytes();
// Called only after the routed tick/pool has drained. Retains counters.
void Stop();
// Executes the entire stage, including the untouched original on preflight refusal.
uint32_t __fastcall Stage(void* manager);
// Guards any fallback or non-COLLIDE route to 0x57DC30/SOFT_ACTIVE: when a rebuild tick has
// max(+0x24C, +0x260) > 0x10020 (the 65,568-bit stack bitmap limit of 0x57DC30), increments
// RebuildGuards() (and *guardCounter when non-null) and executes the stage with a 131,072-bit
// bitmap (or the reuse loop above 131,072) instead of calling stageFn.
uint32_t GuardedStage(void* manager, uint32_t stageFn, uint32_t queryFn, uint32_t freeFn, volatile uint32_t* guardCounter = nullptr);
uint32_t RebuildGuards();
void Sample(uint32_t words[WordCount]);
void SampleSource(uint32_t words[SourceWordCount]);
// Oracle seam, owner only, between stages: the most recent stage's contact plan rows
// (plans[0, rows) in contact order; null without a contact mode) and the number of Predict
// calls its plan phase made (counted at prediction, per chunk). Zero rows when no plan phase ran.
const ntw2_contact::Plan* ContactPlans(uint32_t& rows, uint32_t& predicted);
}
