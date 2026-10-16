// Slice C oracle cases: class-wrapper (0x132BA04 / 0x5B2CA0) occurrences on owned workers, included by native_loco_oracle.cpp.
#pragma once
namespace classwrap {

// Phase 1: a wrapper with no pre-step (+688 == 0) and an empty child array (+66C == 0) is exactly its 0x62A290 selector call and runs
// on workers; a pre-step or a child list stays on the owner. Compared with the untouched original 0x531AF0 by OwnedStageOnce.
static Scenario Mixed(U count, bool wrapperBattle) {
    Scenario sc = OwnedScenario(count, wrapperBattle);
    for (U i = 0; i < sc.agents.size(); ++i) if (i % 3 == 1) sc.agents[i].vt = VtClass;   // empty class wrappers
    return sc;
}
// Phase 2: wrappers whose children are real World agents (0x1333714) run on workers through the participant LOCO_CLASS_WRAP
// clone with proxy children; the owner replays native 0x80BAC0 per child at the wrapper's ordinal. Compared with the untouched
// original 0x531AF0 (children, receivers, native chains) by OwnedStageOnce; results equal across lane counts and orders.
static Scenario Phase2Mixed(bool battle, OwnedPlan& plan) {
    Scenario sc = OwnedScenario(24, battle);
    auto wrap = [&](U w, std::vector<U> kids, U state = 0) {
        sc.agents[w].vt = VtClass; sc.agents[w].kids = std::move(kids); sc.agents[w].b224 = state;
        ++plan.details[loco::OwnedDetailClassWrapper];
    };
    wrap(9, {2});            // one child, earlier in the worklist (already committed when the wrapper relocates it)
    wrap(12, {4, 5});        // two children
    wrap(15, {6, 7, 8});     // three children
    wrap(18, {1}, 8);        // state 8: the child loop skips every child, no relocation
    wrap(20, {22});          // child later in the worklist: an owner-run alternate wrapper that sees the relocated pose
    sc.agents[22].ec = 0; sc.agents[22].b628 = 1; sc.agents[22].b62c = 4;
    plan.details[loco::OwnedDetailAlternate] = 1;
    plan.owner[22] = true; plan.alternateRefusals = 1;
    plan.cwAdmitted = 5; plan.cwEvents = 1 + 2 + 3 + 0 + 1;
    return sc;
}
static void Phase2Cases() {
    StageGatherPatch gather;
    for (const U mode : {2u, 1u}) for (const bool battle : {false, true}) {
        std::vector<U> reference;
        for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
            currentCase = mode == 2 ? "class wrappers phase 2: World agent children live on workers, owner replays 80BAC0"
                                    : "class wrappers phase 2 shadow: workers compute, native runs and compares";
            OwnedPlan plan; plan.lanes = lanes; plan.concurrent = lanes > 1; plan.reversed = reversed; plan.cw = mode;
            const Scenario sc = Phase2Mixed(battle, plan);
            if (mode == 1) for (U w : {9u, 12u, 15u, 18u, 20u}) plan.owner[w] = plan.attempted[w] = true;
            const auto result = OwnedStageOnce(sc, plan);
            if (reference.empty()) reference = result;
            else Require(result == reference, "phase 2 result is identical across lane counts and chunk orders");
        }
    }
    for (U lanes : {1u, 4u, 8u}) {
        currentCase = "class wrappers phase 2: over-full and non-agent child lists stay on the owner";
        Scenario sc = OwnedScenario(24, true);
        OwnedPlan plan; plan.lanes = lanes; plan.concurrent = lanes > 1; plan.cw = 2;
        sc.agents[11].vt = VtClass; sc.agents[11].kids = {0, 1, 2, 3, 4, 5, 6, 7, 8};        // nine children (> 8): gate refusal
        sc.agents[12].vt = VtClass; sc.agents[12].classMutate = true; sc.agents[12].arg = 12; // host child vtable: class refusal
        for (U w : {11u, 12u}) { plan.owner[w] = true; ++plan.classRefusals; ++plan.details[loco::OwnedDetailClassWrapper]; }
        plan.cwRefusedGate = 1; plan.cwRefusedClass = 1;
        OwnedStageOnce(sc, plan);
    }
}
static void ClassWrapperCases() {
    StageGatherPatch gather;
    for (const bool battle : {false, true}) for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
        currentCase = battle ? "class wrappers: empty battle wrappers run on workers" : "class wrappers: empty direct wrappers run on workers";
        OwnedPlan plan; plan.lanes = lanes; plan.concurrent = lanes > 1; plan.reversed = reversed;
        plan.details[loco::OwnedDetailClassWrapper] = 8;   // observed class wrappers
        OwnedStageOnce(Mixed(24, battle), plan);   // classRefusals == 0: nothing refused, census empty
    }
    for (U lanes : {1u, 4u, 8u}) for (bool reversed : {false, true}) {
        currentCase = "class wrappers: pre-step wrappers stay on the owner, siblings stay on workers";
        Scenario sc = Mixed(24, false);
        OwnedPlan plan; plan.lanes = lanes; plan.concurrent = lanes > 1; plan.reversed = reversed;
        plan.details[loco::OwnedDetailClassWrapper] = 8;
        for (U i : {1u, 7u, 13u}) { sc.agents[i].b688 = 2; plan.owner[i] = true; ++plan.classRefusals; }
        OwnedStageOnce(sc, plan);
    }
    for (U lanes : {1u, 4u}) {
        currentCase = "class wrappers: quiet owned mode";
        Scenario sc = Mixed(24, true);
        OwnedPlan plan; plan.lanes = lanes; plan.concurrent = lanes > 1; plan.quiet = true;
        plan.details[loco::OwnedDetailClassWrapper] = 1;   // quiet counts only the owner-run (refused) wrapper
        sc.agents[4].ec = 0; sc.agents[4].b688 = 1; plan.owner[4] = true; ++plan.classRefusals;
        OwnedStageOnce(sc, plan);
    }
    Phase2Cases();
}
} // namespace classwrap
