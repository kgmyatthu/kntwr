#include "kntwr_walk_memo.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include "core/kntwr_guard.h"
#include <string.h>

namespace kntwr_walk_memo {
namespace {
using U = uint32_t;
constexpr U kVertices=64, kSlots=1024, kFixed=13;
struct Key { U words[kFixed+2*kVertices]; };
struct Slot { U epoch, length; Key key; U mxcsrFlags; unsigned short x87Flags; unsigned char result; };
// Static owner storage: no game-heap calls and no allocation during a query.
Slot slots[kSlots];
U epoch, depth;
Kernel nativeKernel;
const U* halfWord;
const U* oneWord;
struct __declspec(align(16)) Fx { unsigned char bytes[512]; };
unsigned short& status(Fx& fx) { return *reinterpret_cast<unsigned short*>(fx.bytes+2); }
U& mxcsr(Fx& fx) { return *reinterpret_cast<U*>(fx.bytes+24); }
bool keyForGuarded(const void* shape, const void* polygon, const Fx& fx, Key& key, U& length, U& hash) {
    // No suppression of unmasked FP traps, no assumptions about a live x87 stack.
    const auto cw=*reinterpret_cast<const unsigned short*>(fx.bytes);
    const auto sw=*reinterpret_cast<const unsigned short*>(fx.bytes+2);
    const U mx=*reinterpret_cast<const U*>(fx.bytes+24);
    if ((cw&0x3f)!=0x3f || (mx&0x1f80)!=0x1f80 || fx.bytes[4] || (sw&0x3800)) return false;
    __try {
        const U* s=static_cast<const U*>(shape);
        if (s[0]!=0) return false; // Triangle closure is not included in this proof.
        // 0x10EC150 reads OBB +0,+4,+0xC..+0x20 (relative to shape+4).
        // +8 is angle/padding and is not an input of this predicate.
        key.words[0]=s[1]; key.words[1]=s[2];
        for (U i=0;i<6;++i) key.words[2+i]=s[4+i];
        key.words[8]=cw|(static_cast<U>(sw&0x3f)<<16); key.words[9]=mx;
        key.words[10]=*halfWord; key.words[11]=*oneWord;
        const U* node=static_cast<const U*>(polygon);
        U count=0;
        do {
            if (count==kVertices) return false;
            key.words[kFixed+2*count]=node[3];
            key.words[kFixed+2*count+1]=node[4];
            ++count;
            node=reinterpret_cast<const U*>(node[2]);
        } while (node!=polygon);
        key.words[12]=count;
        length=kFixed+2*count;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
    hash=2166136261u;
    for (U i=0;i<length;++i) { hash^=key.words[i]; hash*=16777619u; }
    return true;
}
bool keyFor(const void* shape, const void* polygon, const Fx& fx, Key& key, U& length, U& hash) {
    ++kntwr::probeDepth; // the __try in keyForGuarded catches faults on the game's polygon list: not a crash (CrashVeh)
    const bool ok=keyForGuarded(shape,polygon,fx,key,length,hash);
    --kntwr::probeDepth;
    return ok;
}
}
volatile uint32_t counters[4];
void configure(Kernel original, const U* half, const U* one) {
    nativeKernel=original; halfWord=half; oneWord=one; depth=0;
}
void begin() {
    if (depth++) return;
    if (!++epoch) { memset(slots,0,sizeof(slots)); epoch=1; }
}
void end() { if (depth) --depth; }
unsigned char __fastcall kernel(void* shape, void*, void* polygon) {
    Fx before;
    _fxsave(before.bytes);
    ++counters[0];
    Key key;
    U length=0, hash=0;
    const bool supported=depth && keyFor(shape,polygon,before,key,length,hash);
    Slot* slot=supported ? &slots[hash&(kSlots-1)] : nullptr;
    if (slot && slot->epoch==epoch && slot->length==length &&
        !memcmp(slot->key.words,key.words,length*sizeof(U))) {
        ++counters[1];
        const unsigned char result=slot->result;
        // Native fld/fabs/fstp is balanced, leaves C0/C2/C3 and TOP unchanged,
        // sets C1, and accumulates sticky exceptions. SSE also accumulates flags.
        // Preserve the caller's controls and live register values, never replay
        // another invocation's pointers or floating-point stack contents.
        status(before)=static_cast<unsigned short>((status(before)&~0x200u)|slot->x87Flags);
        mxcsr(before)|=slot->mxcsrFlags;
        _fxrstor(before.bytes);
        return result;
    }
    if (supported) ++counters[2]; else ++counters[3];
    _fxrstor(before.bytes);
    const unsigned char result=nativeKernel(shape,nullptr,polygon);
    Fx after;
    _fxsave(after.bytes);
    if (slot) {
        slot->epoch=epoch; slot->length=length;
        memcpy(slot->key.words,key.words,length*sizeof(U));
        slot->result=result;
        slot->mxcsrFlags=mxcsr(after)&0x3f;
        slot->x87Flags=static_cast<unsigned short>(status(after)&0x23f);
    }
    _fxrstor(after.bytes);
    return result;
}
}
