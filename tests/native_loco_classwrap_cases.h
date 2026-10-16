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
}
} // namespace classwrap
