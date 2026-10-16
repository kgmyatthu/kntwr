#ifndef NTW2_CLONES_H
#define NTW2_CLONES_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Build-time metadata describes only this pinned image. No disassembler or
   Python runs inside the game. All source bytes are read from the validated
   live image, never from an embedded replacement executable. */
enum ntw2_binding {
    NTW2_BIND_TICK_ENTRY,      /* TASK's call of the original tick 0x57DF40: guard that reaches CLONE_TICK or the original */
    NTW2_BIND_BAL_MANAGER,     /* TICK's call of the original 0x6F6BC0: guard choosing CLONE_BAL_MANAGER or the original */
    NTW2_BIND_FORM_MANAGER, NTW2_BIND_FORM_ASSIGN,
    NTW2_BIND_BAL_STAGE, NTW2_BIND_BAL_STEP, NTW2_BIND_BAL_JOB,
    NTW2_BIND_QUERY_GATHER, NTW2_BIND_QUERY_UNIT, NTW2_BIND_QUERY,
    NTW2_BIND_BATCH_APPEND, NTW2_BIND_BATCH_FLUSH,
    NTW2_BIND_PATH_HOOK,       /* TICK's call at 0x57DFEA of the original scheduler 0x81A2C0: npr_scheduler_hook (fastcall, ecx = pf) */
    NTW2_BIND_PATH_SOLVE,      /* PATH_STEPPER's call at 0x8101F5 of the original solver 0x8026F0: npr_solve (callee pops 0x14) */
    /* Inclusive ACTIVE (0..15), ARMY (16..20), AIPASS (21..24), ARMIES (25) and AICTRL (26..39) sites; see ntw2_runtime.h. */
    NTW2_BIND_SITE_CALL_0, NTW2_BIND_SITE_CALL_1, NTW2_BIND_SITE_CALL_2, NTW2_BIND_SITE_CALL_3,
    NTW2_BIND_SITE_CALL_4, NTW2_BIND_SITE_CALL_5, NTW2_BIND_SITE_CALL_6, NTW2_BIND_SITE_CALL_7,
    NTW2_BIND_SITE_CALL_8, NTW2_BIND_SITE_CALL_9, NTW2_BIND_SITE_CALL_10, NTW2_BIND_SITE_CALL_11,
    NTW2_BIND_SITE_CALL_12, NTW2_BIND_SITE_CALL_13, NTW2_BIND_SITE_CALL_14, NTW2_BIND_SITE_CALL_15,
    NTW2_BIND_SITE_CALL_16, NTW2_BIND_SITE_CALL_17, NTW2_BIND_SITE_CALL_18, NTW2_BIND_SITE_CALL_19,
    NTW2_BIND_SITE_CALL_20, NTW2_BIND_SITE_CALL_21, NTW2_BIND_SITE_CALL_22, NTW2_BIND_SITE_CALL_23,
    NTW2_BIND_SITE_CALL_24, NTW2_BIND_SITE_CALL_25, NTW2_BIND_SITE_CALL_26, NTW2_BIND_SITE_CALL_27,
    NTW2_BIND_SITE_CALL_28, NTW2_BIND_SITE_CALL_29, NTW2_BIND_SITE_CALL_30, NTW2_BIND_SITE_CALL_31,
    NTW2_BIND_SITE_CALL_32, NTW2_BIND_SITE_CALL_33, NTW2_BIND_SITE_CALL_34, NTW2_BIND_SITE_CALL_35,
    NTW2_BIND_SITE_CALL_36, NTW2_BIND_SITE_CALL_37, NTW2_BIND_SITE_CALL_38, NTW2_BIND_SITE_CALL_39,
    NTW2_BIND_SITE_CALL_40, NTW2_BIND_SITE_CALL_41, NTW2_BIND_SITE_CALL_42, NTW2_BIND_SITE_CALL_43,
    NTW2_BIND_SITE_CALL_44, NTW2_BIND_SITE_CALL_45,
    /* Brain profiling (NTW2_BRAIN): class entry (46..50), wrapper callee (51..64) and brain-callee (65..94) sites; see ntw2_runtime.h. */
    NTW2_BIND_SITE_CALL_46, NTW2_BIND_SITE_CALL_47, NTW2_BIND_SITE_CALL_48, NTW2_BIND_SITE_CALL_49,
    NTW2_BIND_SITE_CALL_50, NTW2_BIND_SITE_CALL_51, NTW2_BIND_SITE_CALL_52, NTW2_BIND_SITE_CALL_53,
    NTW2_BIND_SITE_CALL_54, NTW2_BIND_SITE_CALL_55, NTW2_BIND_SITE_CALL_56, NTW2_BIND_SITE_CALL_57,
    NTW2_BIND_SITE_CALL_58, NTW2_BIND_SITE_CALL_59, NTW2_BIND_SITE_CALL_60, NTW2_BIND_SITE_CALL_61,
    NTW2_BIND_SITE_CALL_62, NTW2_BIND_SITE_CALL_63, NTW2_BIND_SITE_CALL_64, NTW2_BIND_SITE_CALL_65,
    NTW2_BIND_SITE_CALL_66, NTW2_BIND_SITE_CALL_67, NTW2_BIND_SITE_CALL_68, NTW2_BIND_SITE_CALL_69,
    NTW2_BIND_SITE_CALL_70, NTW2_BIND_SITE_CALL_71, NTW2_BIND_SITE_CALL_72, NTW2_BIND_SITE_CALL_73,
    NTW2_BIND_SITE_CALL_74, NTW2_BIND_SITE_CALL_75, NTW2_BIND_SITE_CALL_76, NTW2_BIND_SITE_CALL_77,
    NTW2_BIND_SITE_CALL_78, NTW2_BIND_SITE_CALL_79, NTW2_BIND_SITE_CALL_80, NTW2_BIND_SITE_CALL_81,
    NTW2_BIND_SITE_CALL_82, NTW2_BIND_SITE_CALL_83, NTW2_BIND_SITE_CALL_84, NTW2_BIND_SITE_CALL_85,
    NTW2_BIND_SITE_CALL_86, NTW2_BIND_SITE_CALL_87, NTW2_BIND_SITE_CALL_88, NTW2_BIND_SITE_CALL_89,
    NTW2_BIND_SITE_CALL_90, NTW2_BIND_SITE_CALL_91, NTW2_BIND_SITE_CALL_92, NTW2_BIND_SITE_CALL_93,
    NTW2_BIND_SITE_CALL_94,
    /* ARMY_UPDATE (0x580390): every direct call, sites 95..105. */
    NTW2_BIND_SITE_CALL_95, NTW2_BIND_SITE_CALL_96, NTW2_BIND_SITE_CALL_97, NTW2_BIND_SITE_CALL_98,
    NTW2_BIND_SITE_CALL_99, NTW2_BIND_SITE_CALL_100, NTW2_BIND_SITE_CALL_101, NTW2_BIND_SITE_CALL_102,
    NTW2_BIND_SITE_CALL_103, NTW2_BIND_SITE_CALL_104, NTW2_BIND_SITE_CALL_105,
    /* PROFILE collision query, u16 append, oriented radius and type-8 callback. */
    NTW2_BIND_SITE_CALL_106, NTW2_BIND_SITE_CALL_107, NTW2_BIND_SITE_CALL_108, NTW2_BIND_SITE_CALL_109,
    /* unsigned __fastcall VisualLoop(void *self): ECX=this, EDX ignored, no stack args; preserves nonvolatiles.
       Returns the last first-loop item's original status byte (zero-extended) for the entry's 0x708870 tail. */
    NTW2_BIND_VISUAL_LOOP,
    NTW2_BIND_COLLISION_REUSE, NTW2_BIND_COLLISION_REBUILD, NTW2_BIND_COLLISION_ACCEPT,
    NTW2_BIND_COLLISION_LABEL, NTW2_BIND_COLLISION_NUMERIC_BEGIN, NTW2_BIND_COLLISION_NUMERIC_END,
    NTW2_BIND_COLLIDE_QUERY, /* ECX=record, EDX ignored, scratch on stack, ret 4 */
    /* LOCO is one owner participant. Bind scratch before emission; Start explicitly constructs headers/backing.
       14543B4: 20 bytes [vptr,0,capacity,count,data]; 15A1888/15A189C: 16 bytes [0,capacity,count,data].
       Every interior operand is rebased. Guard bindings are private too, although warm clones remove all TLS/init.
       Native backing uses 444B40(count,ignored), freed with FF7EF0; element destructor 444B60 is pinned RET. */
    NTW2_BIND_LOCO_SCRATCH_14543B4, NTW2_BIND_LOCO_SCRATCH_15A1888, NTW2_BIND_LOCO_SCRATCH_15A189C,
    NTW2_BIND_LOCO_GUARD_15A1884, NTW2_BIND_LOCO_GUARD_15A1898, NTW2_BIND_LOCO_GUARD_15A18AC,
    /* Naked transparent owner-service forwarding thunks: preserve original registers/flags/FP and stack ABI.
       Four grid services: ECX=agent, no stack args, RET.
       801140: ECX=agent, (scratch triplet*, swept AABB*, mode), RET 12.
       80F290: ECX=agent, (scratch triplet*, swept AABB*), RET 8, AL result.
       81AE40: ECX=agent, (scratch triplet*), RET 4. 814AA0: ECX=agent+F4, RET, AL result.
       The triplet contains pointers to the three headers above; helpers stay synchronous on the owner. */
    NTW2_BIND_LOCO_SERVICE_811ED0, NTW2_BIND_LOCO_SERVICE_811D50,
    NTW2_BIND_LOCO_SERVICE_7EFDD0, NTW2_BIND_LOCO_SERVICE_7EFA80,
    NTW2_BIND_LOCO_SERVICE_801140, NTW2_BIND_LOCO_SERVICE_80F290,
    NTW2_BIND_LOCO_SERVICE_81AE40, NTW2_BIND_LOCO_SERVICE_814AA0,
    NTW2_BIND_LOCO_STAGE_GATHER, /* selector call 62A2F8 -> owner 7FC120; starts staging interval */
    NTW2_BIND_LOCO_STAGE_RESET,  /* selector tail jump 62A30D -> owner 7F7140; ends interval after return */
    NTW2_BIND_AI_CENSUS_REBUILD, /* AI_CONTROLLER calls 7C8C5A/7C8C83 of planner rebuild 7492F0 (thiscall, ret 4): census gate forwards to the original */
    /* BRAIN2 v2 private forwarding gates. Metadata is pushed by generated
       source-pinned thunks; native registers, EFLAGS, x87/SSE and RET n survive. */
    NTW2_BIND_B2_SERVICE_GATE, NTW2_BIND_B2_OBSERVE,
    /* Participant-private reference-node projection (7FD070/81C080/81C050/67A790), NTW2_NODE_PROJ_PARTICIPANTS copies.
       VISIT_p: address of the private image of 15ADB74..15AFBA3 (ring header @+0, ring guard @+0x14, bitset @+0x1C,
       id-vector header @+0x201C, id guard @+0x202C), congruent mod 16 with the original. LOOKUP_p: private image of
       14D0A6C..14D0A7F (16-byte candidate vector [tag,capacity,count,data] then its guard). Host Initialize constructs
       both zeroed (the originals are BSS); warm clones never read the guards, TLS or atexit registration. */
    NTW2_BIND_NODE_PROJ_VISIT_0, NTW2_BIND_NODE_PROJ_VISIT_1, NTW2_BIND_NODE_PROJ_VISIT_2,
    NTW2_BIND_NODE_PROJ_VISIT_3, NTW2_BIND_NODE_PROJ_VISIT_4, NTW2_BIND_NODE_PROJ_VISIT_5,
    NTW2_BIND_NODE_PROJ_VISIT_6, NTW2_BIND_NODE_PROJ_VISIT_7, NTW2_BIND_NODE_PROJ_VISIT_8,
    NTW2_BIND_NODE_PROJ_LOOKUP_0, NTW2_BIND_NODE_PROJ_LOOKUP_1, NTW2_BIND_NODE_PROJ_LOOKUP_2,
    NTW2_BIND_NODE_PROJ_LOOKUP_3, NTW2_BIND_NODE_PROJ_LOOKUP_4, NTW2_BIND_NODE_PROJ_LOOKUP_5,
    NTW2_BIND_NODE_PROJ_LOOKUP_6, NTW2_BIND_NODE_PROJ_LOOKUP_7, NTW2_BIND_NODE_PROJ_LOOKUP_8,
    NTW2_BIND_NODE_PROJ_CELL, NTW2_BIND_NODE_PROJ_EDGE, NTW2_BIND_NODE_PROJ_DESCRIPTOR,
    /* NTW2_AI_ASYNC2 (appended). AI2_SPATIAL_JOIN: TICK's call 57DFDF of the dynamic quadtree update 817D20 (thiscall
       ECX = model+C0, plain ret): transparent naked gate that joins an in-flight async think, then tail-jumps to 817D20.
       AI2_WALK_IMAGE: worker-private image of 15AFBA8..15AFDBB (search object 15AFBA8 + guard 15AFCA4, search object
       15AFCA8 + guard 15AFDA4, walk output vector 15AFDA8 + guard 15AFDB8), congruent mod 16 with the original.
       AI2_GATHER_IMAGE: private image of 15BBF4C..15BBF5F (interest-gather output vector + guard 15BBF5C).
       AI2_LOOKUP_IMAGE: private image of 14D0A6C..14D0A7F (projection lookup vector + guard).
       AI2_ROOT_INTEREST: replaces `mov esi,[eax+0BC]` at 7F1D73 (AI2_WALK): EAX = model in, ESI = interest tree
       object out; every other register and EFLAGS preserved. Default resolves the live root; a retained read
       generation substitutes its own root here. */
    NTW2_BIND_AI2_SPATIAL_JOIN, NTW2_BIND_AI2_WALK_IMAGE, NTW2_BIND_AI2_GATHER_IMAGE, NTW2_BIND_AI2_LOOKUP_IMAGE,
    NTW2_BIND_AI2_ROOT_INTEREST,
    /* NTW2_AI_ASYNC2 observer route (appended). AI2_SPOT_IMAGE: private image of 150B5F8..150B6F7 (6C71D0's search object +
       guard 150B6F4), congruent mod 16. AI2_ROUTE_COUNTS: address of the runtime's per-private-function entry counters (one
       dword per generator AI2_ROUTE_ORDER index, incremented at each clone entry; AI worker is the only writer).
       AI2_UNROUTED_83FD00: gate for AI2_POSITION_UPDATE's call 7A6D1D of 83FD00 (thiscall, ret 18): marshals the whole call
       to the tick owner while an async think runs, else tail-jumps the original. */
    NTW2_BIND_AI2_SPOT_IMAGE, NTW2_BIND_AI2_ROUTE_COUNTS, NTW2_BIND_AI2_UNROUTED_83FD00,
    NTW2_BIND_COUNT
};
enum ntw2_clone_id {
    NTW2_CLONE_TICK, NTW2_CLONE_TASK,
    NTW2_CLONE_FORM_COMMAND, NTW2_CLONE_FORM_HELPER, NTW2_CLONE_FORM_ASSIGN,
    NTW2_CLONE_BAL_PREFIX, NTW2_CLONE_BAL_MANAGER, NTW2_CLONE_BAL_STEP,
    NTW2_CLONE_BAL_ITEM, NTW2_CLONE_QUERY, NTW2_CLONE_QUERY_TABLE, NTW2_CLONE_QUERY_WRAPPER,
    NTW2_CLONE_BATCH_CALLEE, NTW2_CLONE_BATCH_WORKER,
    NTW2_CLONE_PATH_SCHEDULER, /* 0x81A2C0 body; its call at 0x81A361 reaches CLONE_PATH_STEPPER */
    NTW2_CLONE_PATH_STEPPER,   /* 0x80F5E0 body; its call at 0x8101F5 reaches BIND_PATH_SOLVE */
    NTW2_CLONE_UNIT_HIT,       /* 0x809620 private-unit worker: the two virtual getters read the private unit snapshot */
    NTW2_CLONE_MANAGER,       /* 0x580640..0x58094C and embedded rebased eight-entry switch table */
    NTW2_CLONE_ACTIVE,        /* 0x583480..0x583566; sixteen call sites route through host timing thunks */
    NTW2_CLONE_ARMIES,        /* 0x582FB0..0x5830FB; army loop calls CLONE_ARMY, CLONE_AIPASS (x2) and timed 0x550240 */
    NTW2_CLONE_AIPASS,        /* 0x5832C0..0x583371; four calls (0x55AD60 x2, per-army 0x539E80 and 0x583380) are timed */
    NTW2_CLONE_ARMY,          /* 0x580320..0x580387; four calls and the army AI tail are timed */
    NTW2_CLONE_ARMY_UPDATE,   /* 0x580390..0x5805D5; site 18's body, eleven timed direct calls */
    NTW2_CLONE_AIWRAP,        /* 0x583380..0x58338C; non-null controller conditionally tail-jumps to CLONE_AICTRL */
    NTW2_CLONE_AICTRL,        /* 0x7B25A0..0x7B274E; fourteen direct calls are timed as sites 26..39 */
    NTW2_CLONE_AI_STATE_UPDATE,    /* 0x702BB0: vtable 0x133E2D4 slot +8 */
    NTW2_CLONE_AI_POSITION_UPDATE, /* 0x7A6960: calls AI_SHAPE_SEARCH */
    NTW2_CLONE_AI_SHAPE_SEARCH,    /* 0x7C7DC0: walk sites 0x7C7FD3 and 0x7C8113 */
    NTW2_CLONE_AI_WALK,       /* 0x7F1D40: gather and polygon predicate seams */
    NTW2_CLONE_AI_GATHER,     /* 0x804DD0: spatial candidate traversal and active-interest filter */
    NTW2_CLONE_PLANNER,       /* 0x7D99F0..0x7D9B13: PROFILE-only attribution; all original virtual calls intact */
    NTW2_CLONE_BRAIN,         /* 0x66CE00..0x66D6BC: agent brain step (slot +0x0C); every direct callee and two virtual calls are timed sites, rebased two-entry switch table at 0x8BC */
    NTW2_CLONE_WRAP_6F4660,   /* 0x6F4660..0x6F4697: class wrapper (LOS/registration pre-steps); callees and the brain call are timed sites */
    NTW2_CLONE_WRAP_602EB0,   /* 0x602EB0..0x602F49: class wrapper (brain, then two post steps); all calls are timed sites */
    NTW2_CLONE_WRAP_5FCEB0,   /* 0x5FCEB0..0x5FCFAB: class wrapper (brain, four post steps, timed 0x5B9720 tail) */
    NTW2_CLONE_VISUAL_ENTRY, /* 0x779E60..0x77A162: ECX=this, one unused stack argument, ret 4, void;
                              original one-shot/prelude and entire serial tail, first loop replaced by VISUAL_LOOP */
    NTW2_CLONE_VISUAL_ITEM,  /* 0x779EA4..0x77A025: unsigned __fastcall(void *self, uint32_t index), plain ret;
                              original body with stack locals/nonvolatiles, returns original [esp+13] status byte */
    NTW2_CLONE_SOFT_ACTIVE, /* PROFILE/COLLIDE_LOD 0x57DC30 stage; three queries routed through the host gate */
    NTW2_CLONE_COLLIDE_Q,   /* PROFILE-only 0x81A790; original ordered arithmetic/callbacks intact */
    NTW2_CLONE_LOCO_WRAP,       /* 7F0260..7F05F0: ECX=agent, RET; integrates once through LOCO_MOVE */
    NTW2_CLONE_LOCO_MOVE,       /* 7F08F0..7F14BE: private scratch, explicit host construction, owner services */
    NTW2_CLONE_LOCO_SELECT,     /* 62A290..62A34D: exact latches/branch; host-timed original staging and 7F7140 reset */
    NTW2_CLONE_LOCO_CLASS_WRAP, /* 5B2CA0..5B2E48: 132BA04:+10, full wrapper calling LOCO_SELECT */
    NTW2_CLONE_AI_CONTROLLER,   /* 7C8BD0..7C8C8C + 9-entry switch table: AI controller job body; only its two 7492F0 calls are retargeted (AI_CENSUS) */
    NTW2_CLONE_BRAIN_W, NTW2_CLONE_BRAIN_W_602EB0, NTW2_CLONE_BRAIN_W_5FCEB0,
    NTW2_CLONE_BRAIN_W_TRIGGER, NTW2_CLONE_BRAIN_W_MOVEORDER, NTW2_CLONE_BRAIN_W_DRIVER,
    NTW2_CLONE_BRAIN_W_WATCHER, NTW2_CLONE_BRAIN_W_FINALIZE, NTW2_CLONE_BRAIN_W_FIRE,
    NTW2_CLONE_BRAIN_W_REFERENCE, NTW2_CLONE_BRAIN_W_BEGIN, NTW2_CLONE_BRAIN_W_STEP,
    NTW2_CLONE_BRAIN_W_REQUEST, NTW2_CLONE_BRAIN_W_CANDIDATES,
    NTW2_CLONE_BRAIN_W_CANDIDATE_BODY, NTW2_CLONE_BRAIN_W_GATHER,
    NTW2_CLONE_BRAIN_W_TARGET, NTW2_CLONE_BRAIN_W_WRAPPER_SERVICE,
    NTW2_CLONE_BRAIN_W_FINISH, NTW2_CLONE_BRAIN_W_RECYCLE,
    NTW2_CLONE_BRAIN_W_BACKLINK, NTW2_CLONE_BRAIN_W_BACKUNLINK,
    NTW2_CLONE_BRAIN_W_TIMER, NTW2_CLONE_BRAIN_W_ANIMATION,
    NTW2_CLONE_BRAIN_W_SLOT, NTW2_CLONE_BRAIN_W_RESET_REQUEST,
    NTW2_CLONE_BRAIN_W_PARKED, NTW2_CLONE_BRAIN_W_ORDER, NTW2_CLONE_BRAIN_W_NODE_ORDER,
    NTW2_CLONE_BRAIN_W_ARRIVAL, NTW2_CLONE_BRAIN_W_UNLINK,
    /* Per participant p (0..8) four contiguous clones, in this order: 7FD070 (entry), 81C080, 81C050, 67A790. */
    NTW2_CLONE_NODE_PROJ_7FD070_0, NTW2_CLONE_NODE_PROJ_81C080_0, NTW2_CLONE_NODE_PROJ_81C050_0, NTW2_CLONE_NODE_PROJ_67A790_0,
    NTW2_CLONE_NODE_PROJ_7FD070_1, NTW2_CLONE_NODE_PROJ_81C080_1, NTW2_CLONE_NODE_PROJ_81C050_1, NTW2_CLONE_NODE_PROJ_67A790_1,
    NTW2_CLONE_NODE_PROJ_7FD070_2, NTW2_CLONE_NODE_PROJ_81C080_2, NTW2_CLONE_NODE_PROJ_81C050_2, NTW2_CLONE_NODE_PROJ_67A790_2,
    NTW2_CLONE_NODE_PROJ_7FD070_3, NTW2_CLONE_NODE_PROJ_81C080_3, NTW2_CLONE_NODE_PROJ_81C050_3, NTW2_CLONE_NODE_PROJ_67A790_3,
    NTW2_CLONE_NODE_PROJ_7FD070_4, NTW2_CLONE_NODE_PROJ_81C080_4, NTW2_CLONE_NODE_PROJ_81C050_4, NTW2_CLONE_NODE_PROJ_67A790_4,
    NTW2_CLONE_NODE_PROJ_7FD070_5, NTW2_CLONE_NODE_PROJ_81C080_5, NTW2_CLONE_NODE_PROJ_81C050_5, NTW2_CLONE_NODE_PROJ_67A790_5,
    NTW2_CLONE_NODE_PROJ_7FD070_6, NTW2_CLONE_NODE_PROJ_81C080_6, NTW2_CLONE_NODE_PROJ_81C050_6, NTW2_CLONE_NODE_PROJ_67A790_6,
    NTW2_CLONE_NODE_PROJ_7FD070_7, NTW2_CLONE_NODE_PROJ_81C080_7, NTW2_CLONE_NODE_PROJ_81C050_7, NTW2_CLONE_NODE_PROJ_67A790_7,
    NTW2_CLONE_NODE_PROJ_7FD070_8, NTW2_CLONE_NODE_PROJ_81C080_8, NTW2_CLONE_NODE_PROJ_81C050_8, NTW2_CLONE_NODE_PROJ_67A790_8,
    /* Appended forwarding routes preserve every existing clone ID, including the projection family. */
    NTW2_CLONE_BRAIN_W_COMMON_STEP, /* 670EB0..670F37: common node begin/step and tail to 66EE30 */
    NTW2_CLONE_BRAIN_W_HOLDER_STEP, /* 66C160..66C196: holder node begin/step */
    /* Hot movement-node class 1348B44; source spans include every terminal RET. */
    NTW2_CLONE_BRAIN_W_HOT_BEGIN, NTW2_CLONE_BRAIN_W_HOT_STEP,
    NTW2_CLONE_BRAIN_W_HOT_CTOR, NTW2_CLONE_BRAIN_W_HOT_DTOR,
    NTW2_CLONE_BRAIN_W_HOT_INSTALL, /* 650DC0..650E03: holder replacement reaches hot ctor/dtor */
    NTW2_CLONE_BRAIN_W_IDLE_CTOR, NTW2_CLONE_BRAIN_W_IDLE_BEGIN, NTW2_CLONE_BRAIN_W_IDLE_STEP,
    NTW2_CLONE_BRAIN_W_IDLE_DTOR, NTW2_CLONE_BRAIN_W_IDLE_INSTALL,
    NTW2_CLONE_BRAIN_W_WAIT_CTOR, NTW2_CLONE_BRAIN_W_WAIT_BEGIN, NTW2_CLONE_BRAIN_W_WAIT_STEP,
    NTW2_CLONE_BRAIN_W_WAIT_DTOR, NTW2_CLONE_BRAIN_W_WAIT_INSTALL, NTW2_CLONE_BRAIN_W_STOP,
    NTW2_CLONE_BRAIN_ACTION_BEGIN, NTW2_CLONE_BRAIN_ACTION_STEP,
    NTW2_CLONE_BRAIN_ACTION_RELATED_STEP, NTW2_CLONE_BRAIN_ACTION_RELATED_BEGIN, NTW2_CLONE_BRAIN_ACTION_EMPTY,
    /* NTW2_AI_ASYNC2 worker-private walk family (appended; only the dedicated AI worker enters it, through the
       0x133E2DC slot of 702BB0). Warm entries: each static-init guard branch is NOPped and the private images are
       explicitly host-constructed; scratch operands are rebased to the AI2_*_IMAGE bindings; no site thunks. */
    NTW2_CLONE_AI2_STATE_UPDATE,    /* 702BB0 -> AI2_POSITION_UPDATE */
    NTW2_CLONE_AI2_POSITION_UPDATE, /* 7A6960: 7C7DC0 -> AI2_SHAPE_SEARCH, 7FCA40 -> AI2_7FCA40 */
    NTW2_CLONE_AI2_SHAPE_SEARCH,    /* 7C7DC0: both 7F1D40 calls -> AI2_WALK */
    NTW2_CLONE_AI2_WALK,            /* 7F1D40: 15AFDA8 vector private, 804DD0 -> AI2_GATHER, root load via AI2_ROOT_INTEREST */
    NTW2_CLONE_AI2_GATHER,          /* 804DD0: 15BBF4C vector private */
    NTW2_CLONE_AI2_7FCA40,          /* -> AI2_7FCA90 */
    NTW2_CLONE_AI2_7FCA90,          /* 15AFCA8 search object private; both 808040 calls -> AI2_808040 */
    NTW2_CLONE_AI2_808040,          /* 15AFBA8 search object private; 7F1D40/81C050/7F6F20 -> AI2 clones */
    NTW2_CLONE_AI2_7F6F20,          /* -> AI2_7F1CC0 */
    NTW2_CLONE_AI2_7F1CC0,          /* -> AI2_81C080 */
    NTW2_CLONE_AI2_81C080,          /* -> AI2_81C050 */
    NTW2_CLONE_AI2_81C050,          /* -> AI2_67A790 */
    NTW2_CLONE_AI2_67A790,          /* 14D0A6C lookup vector private (projection warm entry) */
    /* Watcher-node begins (appended BRAIN_W members): 7FF9E0 -> 80A190 -> X.vt+188 (HOT_INSTALL) and
       7FF5C0 -> 809D80 -> X.vt+134 (WAIT_INSTALL); the dispatchers' indirect tails reach the service gate. */
    NTW2_CLONE_BRAIN_W_NODE_BEGIN_7FF9E0, NTW2_CLONE_BRAIN_W_NODE_DISPATCH_80A190,
    NTW2_CLONE_BRAIN_W_NODE_BEGIN_7FF5C0, NTW2_CLONE_BRAIN_W_NODE_DISPATCH_809D80,
    /* NTW2_AI_ASYNC2 observer route (appended): vtable 13376FC slot 16 (6A95A0) is routed by thread to AI2_6A95A0. Every member
       rebases its absolute scratch into the AI2_*_IMAGE bindings and counts its entries in AI2_ROUTE_COUNTS. */
    NTW2_CLONE_AI2_6A95A0,          /* 6C71D0/7FCA40 -> AI2 clones */
    NTW2_CLONE_AI2_6C71D0,          /* 150B5F8 search object private; 6CC730/7F6ED0/7FCA40 -> AI2 clones */
    NTW2_CLONE_AI2_6CC730,          /* -> AI2_808550 */
    NTW2_CLONE_AI2_808550,          /* -> AI2_808040 */
    NTW2_CLONE_AI2_7F6ED0,          /* both 7F1CC0 calls -> AI2_7F1CC0 */
    NTW2_CLONE_AI2_7F1CF0,          /* AI2_7F6F20's slow path; 7F1CC0 -> AI2_7F1CC0 */
    NTW2_CLONE_AI2_809110,          /* gather node traversal (no absolutes); recursion stays private */
    NTW2_CLONE_AI2_80DCF0,          /* AI2_WALK polygon predicate (no absolutes) */
    NTW2_CLONE_COUNT
};
/* Offset inside CLONE_BAL_ITEM of original 0x6F5936 (the BAL_PREFIX tail entry; BAL_ITEM spans 0x6F54E0..0x6F6617 and
   has no insertions before it). The generator asserts this value against the planned layout. */
#define NTW2_BAL_ITEM_TAIL_OFFSET 0x456u
/* Sum of the four one-owner LOCO emitted body sizes, excluding arena alignment; generator asserted. */
#define NTW2_LOCO_CLONE_BYTES 0x1109u
/* Reference-node projection: participants (caller + eight workers) and the sum of ONE participant's four emitted clone
   bodies, excluding arena alignment; generator asserted. */
#define NTW2_NODE_PROJ_PARTICIPANTS 9u
#define NTW2_NODE_PROJ_CLONE_BYTES 0x744u
/* A source span hash is FNV-1a64 over bytes with HIGHLOW relocations normalized
   back to preferred image base 0x400000. Relocation offsets are sorted. */
typedef struct ntw2_source_spec {
    uint32_t va, size;
    uint64_t hash;
    const uint32_t *relocations;
    uint32_t relocation_count;
} ntw2_source_spec;

/* Copy and literal operations are applied first. Fixups then address live game
   image (IMAGE), another emitted clone (CLONE), or a supplied binding (BINDING).
   Relative fixup base is destination field end, not instruction start. */
enum ntw2_target_kind { NTW2_TARGET_IMAGE, NTW2_TARGET_CLONE, NTW2_TARGET_BINDING };
enum ntw2_op_kind { NTW2_COPY, NTW2_LITERAL, NTW2_ABSOLUTE, NTW2_RELATIVE };
typedef struct ntw2_clone_op {
    uint32_t kind, destination, size;
    uint32_t source; /* source-spec index for COPY; target kind for fixups */
    uint32_t offset; /* source offset for COPY; target identifier for fixups */
    int32_t addend;
    const uint8_t *literal;
} ntw2_clone_op;
typedef struct ntw2_clone_spec {
    uint32_t size;
    const ntw2_clone_op *operations;
    uint32_t operation_count;
} ntw2_clone_spec;
typedef struct ntw2_clone_set {
    void *allocation;
    uint32_t allocation_bytes;
    uint32_t entries[NTW2_CLONE_COUNT];
} ntw2_clone_set;

/* Census metadata is generated from analysis/native-grid-reader-census.json.
   Fields name original callsites and emitted fields; targets remain ordinary
   clone fixups, so instrumentation wraps rather than replaces their semantics. */
typedef struct ntw2_grid_reader_spec { uint32_t va, end; } ntw2_grid_reader_spec;
typedef struct ntw2_grid_edge_spec { uint32_t reader, site, clone, field; } ntw2_grid_edge_spec;
typedef struct ntw2_grid_range_spec { uint32_t reader, clone, begin, end; } ntw2_grid_range_spec;
const ntw2_grid_reader_spec* ntw2_grid_reader_specs(uint32_t* count);
const ntw2_grid_edge_spec* ntw2_grid_edge_specs(uint32_t* count);
/* Monitor-only, before building unpublished clones. Zero keeps the old layout
   and call destinations exactly unchanged. Callback is cdecl void(edge_index). */
void ntw2_clones_grid_callback(uint32_t callback);
/* Sampler-only: maps an EIP in a census-built private arena (primary or participant) to a reader index, or
   UINT32_MAX. Arena headers carry the clone entries, so no global allocation registry can dangle. Never
   treats gate time as reader time. Call only after the sampled thread has been resumed. */
uint32_t ntw2_clones_grid_reader(uint32_t eip);
/* Static route class (NTW2_GRID_ROUTE_*) of an edge's resolved destination, from its relative fixup.
   Generator-reported unresolved references (internal calls/direct jumps it cannot gate) are counted here. */
uint32_t ntw2_grid_edge_route(uint32_t edge);
uint32_t ntw2_grid_unresolved_edges(void);
/* Maps an address inside the primary arena `set` to its clone id (*clone, UINT32_MAX when none) and the
   preferred-base original VA of the copied source byte, or 0 for emitted literal bytes / foreign addresses.
   Pure metadata lookup: reads no clone bytes. */
uint32_t ntw2_clone_origin(const ntw2_clone_set* set, uint32_t address, uint32_t* clone);

/* Returns zero on success. Error detail identifies the source or clone index.
   On failure only unpublished storage is released. After publication callers
   must retain allocation until process exit, even after restoring all slots. */
uint32_t ntw2_build_clones(uint32_t image_base, const uint32_t bindings[NTW2_BIND_COUNT],
                          ntw2_clone_set *out, uint32_t *detail);
/* Duplicate the already validated private MOVE/WRAP pair for one pool participant.
   Rewrites metadata-described fixups only, including private scratch bindings;
   never reads or modifies executable image text. The unpublished pair may be
   released once dispatch has joined (no external code pointer is published). */
uint32_t ntw2_build_loco_participant(uint32_t wrap, uint32_t move,
    const uint32_t bindings[NTW2_BIND_COUNT], ntw2_clone_set* out);
/* Duplicate the validated primary BRAIN_W closure (BRAIN_W..BRAIN_W_UNLINK, BRAIN_W_COMMON_STEP..BRAIN_ACTION_EMPTY,
   BRAIN_W_NODE_BEGIN_7FF9E0..BRAIN_W_NODE_DISPATCH_809D80)
   once, rewriting every fixup: bindings from the supplied table (worker service/observe gates), family-internal clone
   targets to the duplicate, other clones to the primary, image targets from metadata. Only member entries are set in
   *out. Never touches image text or the primary arena; the caller releases out->allocation after its last dispatch. */
uint32_t ntw2_build_brain_worker_family(const ntw2_clone_set* primary, uint32_t image_base,
    const uint32_t bindings[NTW2_BIND_COUNT], ntw2_clone_set* out);
#ifdef __cplusplus
}
#endif
#endif
