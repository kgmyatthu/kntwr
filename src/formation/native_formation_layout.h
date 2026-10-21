// Worker-safe port of the Napoleon Total War (x86, SHA-256 13fcab62...cbad4) formation SLOT GENERATOR.
//
// Original chain (static VAs at preferred base 0x400000):
//   0x555CA0 Formation::ApplySlots -> layout->vtable[+0x24](out*, container*, float f, uint men)   (thiscall, ret 0x10)
//     stock Line layout (type 0, vtable 0x1333AA8): 0x62FD60
//     approved modded image: 0x18ED200 (sets process-global flag 0x18ED160 := 1, calls 0x62FD60, flag := 0)
//   0x62FD60:  0x621090 (out vector init, capacity = men, 36-byte records)
//              0x620850/0x61E050/0x61DFA0 (builds the 0x28-byte stack "stepper" ctx, vtable 0x1333AA0)
//              0x659E70 (walks container children: child[0]->vfn+0x18 with the container origin, child[k>0]->vfn+0x14)
//     child classes: A = straight segment (vtable 0x1333944, vfn18 0x659F00), B = arc (vtable 0x133396C, vfn18 0x65A160),
//     both vfn14 = 0x65A130 (start point via vfn+4 = 0x63BF70 / 0x63BF90, then vfn18).
//     each step calls ctx->vfn0 (0x65A3F0 -> 0x65A410 -> 0x619EB0) that emits a column of records
//     (0x80DE00 surface lookup + 0x7FCFF0 position object; 0x65D150 push_back).
//   mod hooks inside 0x619EB0: 0x619FC1 -> 0x18ED0CF and 0x61A109 -> 0x18ED10B, both call 0x18ED164 (gap insertion every 60 files),
//     active only while the global flag 0x18ED160 == 1 and rowLength > 0x3C.
//
// This file contains no globals, no allocation and no pointers into the game. Everything is an explicit immutable snapshot
// gathered on the game thread; output goes to caller-owned contiguous storage.  Floating point is written in the exact order of
// the original SSE/x87 code (build with /fp:strict /arch:SSE2, no FMA contraction); the x87 parts use inline asm with the
// control word captured at gather time (Input::fpuControlWord).
#pragma once
#include <cstddef>
#include <cstdint>

namespace ntw_formation_layout {

// Transform object F reached as *(E->vfn+0x10()->+0x80). Fields are copied raw.
struct Frame {
    float t[3];     // F+0x80,+0x84,+0x88  translation
    float fwd[9];   // F+0x9C,A0,A4,A8,AC,B0,B4,B8,BC  (0x7F4950 local->world)
    float inv[9];   // F+0xC0,C4,C8,CC,D0,D4,D8,DC,E0  (0x7F6820 world->local)
};

// One vertex of a surface cell ring (node: +0x08 next, +0x0C/+0x10 point).  hasLink = (0x6B7F50(node) != 0).
struct SurfaceNode {
    float x, z;
    uint8_t hasLink;
};

// Surface cell E (element of the piece's surface set).  Ring nodes are stored in traversal order starting at the head node E[+8];
// the ring is circular.  plane = E+0x30,+0x34,+0x38,+0x3C.  frame = index into Input::frames or -1 when E->vfn10() is null
// or *(E->vfn10()+0x80) is null.
struct SurfaceCell {
    uint32_t nodeBegin, nodeCount;   // range in Input::nodes
    float plane[4];
    int32_t frame;
};

// Bilinear height grid read by 0x66BB40 -> 0x64C5F0 (only needed for the y component of records whose position is on terrain).
struct HeightField {
    const float* samples;  // 8-byte stride entries (raw copy: sample i is samples[2*i]); only the first dword (float height) of each entry is read
    uint32_t sampleCount;  // number of 8-byte entries readable at `samples` (bounds check; Generate returns kBadInput on an out-of-range index)
    uint32_t shift;        // H+0x08
    int32_t  base;         // H+0x10
    int32_t  limit;        // H+0x14
    float    half;         // H+0x1C : clamp half-extent in 0x66BB40 and origin offset in 0x64C5F0
    float    cell;         // H+0x20
    float    scale;        // H+0x24
};

// Child object of the container (class A or B), raw fields at their object offsets.
struct Piece {
    uint8_t  isArc;          // 0 = class A (vtable 0x1333944), 1 = class B (vtable 0x133396C)
    int32_t  mode;           // child+0x04 (B compares == 2)
    uint16_t angle;          // child+0x08
    float    p0[2];          // child+0x0C,+0x10   (A start)
    float    p1[2];          // child+0x14,+0x18   (A end / B end)
    float    step[2];        // child+0x60,+0x64   (A entry step direction)
    float    width;          // child+0x70         (A entry width)
    float    arcStart[2];    // child+0x7C,+0x80   (B vfn+4 start point)
    float    dir[2];         // child+0x8C,+0x90
    float    center[2];      // child+0x98,+0x9C   (B)
    float    arcWidth;       // child+0xA0         (B entry width)
    uint32_t cellBegin, cellCount;   // surface set O = {inline list, then overflow list} flattened in 0x80DE00 iteration order
};

// Position object {x,y,z, parent frame}.  Used for the container origin (container+0x18 .. +0x28, resolved with 0x80E9D0).
struct PosObj {
    float x, y, z;
    int32_t frame;           // index into Input::frames or -1 (word at +0x10 of the object)
};

struct Input {
    uint32_t men;            // 0x62FD60 arg4 = formation+0x18: out vector capacity and the initial "remaining" count
    float f;                 // arg3 (cmd+0x1C), ctx[4]
    float layout8, layoutC, layout10, layout14;   // layout object +8,+0xC,+0x10,+0x14 (ctx[8], ctx[0xC], ctx[0x24], ctx[0x10])
    PosObj origin;           // container+0x18 (position object resolved through 0x80E9D0)
    const Piece* pieces; uint32_t pieceCount;     // container children in order
    const SurfaceCell* cells; uint32_t cellCount;
    const SurfaceNode* nodes; uint32_t nodeCount;
    const Frame* frames; uint32_t frameCount;
    const HeightField* terrain;                   // may be null: y of terrain-resident records is then NaN-free 0 and yValid=0
    uint8_t modActive;       // process flag 0x18ED160 == 1 during the call (layout vtable[+0x24]==0x18ED200 path)
    uint16_t fpuControlWord; // x87 control word of the game thread at gather (0 = keep the calling thread's)
};

struct Slot {
    uint8_t flag;            // record+0x00
    float x, y, z;           // record+0x04..+0x0C (local to `frame`)
    int32_t cell;            // record+0x10 as index into Input::cells (-1 none)
    int32_t frame;           // record+0x14 as index into Input::frames (-1 none)
    uint16_t angle;          // record+0x18
    float worldX, worldY, worldZ;   // 0x80E9D0(record+4)
    uint8_t yValid;          // 0 when y could not be computed (terrain==null)
};

struct Result {
    uint32_t count;          // out->+8
    uint32_t mark;           // out->+0x10 (set to count when the first placement of the walk is emitted)
};

enum Status : int { kOk = 0, kCapacity = 1, kBadInput = 2 };

// out must hold in.men Slot entries.  Records never exceed men (remaining is decremented per record).
int Generate(const Input& in, Slot* out, uint32_t capacity, Result* result);

// Adapter to ntw_formation::SlotInput (native_formation_slot.h): slotX = worldX, slotZ = worldZ, slotAngle = angle.
void ToSlotArrays(const Slot* slots, uint32_t count, float* slotX, float* slotZ, uint16_t* slotAngle);

}  // namespace ntw_formation_layout
