#pragma once
#include <stdint.h>

// Exact C++ port of the formation command queue walk 0x581E80 (thiscall, ECX = Q = F+0x20, plain ret) for the single call site
// 0x580B7A of the infantry formation update 0x580A30 (the private CLONE_FORM_UPDATE under --army-storm-census). Diagnostic only:
// the port exists so each per-command callback can be timed and attributed to its command class; it is NOT a performance change.
// The separate tail entry 0x580970 keeps running the native function. All callbacks, 0x56D990 and every destructor stay native.
//
// Native contract [proven by disasm, analysis/army-formation-closure.asm:12034-12084 and 9854-9886]. Q+0x400 is an inline array
// of 8-byte entries {command, size}; dword Q+0x440 = count; byte Q+0x450 = iterating, byte Q+0x451 = dirty, dword Q+0x454 = index.
//   word [Q+450] = 1 (iterating 1, dirty 0); if count == 0 skip the loop (unsigned compare);
//   loop: if byte [Q+450] != 1 stop; count = [Q+440] (sampled here, i == count-1 below uses THIS sample); [Q+454] = i;
//     cmd = [Q+400+8i]; vtbl = [cmd] (both read before the callback); then
//     i == count-1: call [vtbl+4] (ECX = cmd, EDX = vtbl, no stack argument); if byte [Q+451] != 0 byte [Q+450] = 0;
//       inc dword [cmd+0x10] and read byte [cmd+0xC] on the SAVED cmd (the register, not the entry: callbacks may replace or
//       delete the entry); if that byte == 1 call 0x56D990(ECX = Q, push i, ret 4);
//     otherwise: call [vtbl+8]; if byte [Q+451] != 0 byte [Q+450] = 0;
//     i++; [Q+454] = 0xFFFFFFFF; continue while i < [Q+440] (unsigned, re-read after every callback; nothing is cached across calls);
//   byte [Q+450] = 1 on every exit path.
// 0x56D990 returns at once when byte [Q+450] == 0 (so a dirty last callback skips the erase); otherwise it erases from the tail
// down to index i, calling each entry's deleting destructor [[cmd]+0] (push 1, callee pops) and adjusting [Q+444]/[Q+448].
// EAX of 0x581E80 is the last callback's/erase's EAX (the caller's own EAX when count == 0); no caller needs it: 0x580B7A is
// followed by `lea ecx,[esi+74C]; call 0x551A40` and 0x551A40 (tail 0x542AA0) writes EAX before any read. Run therefore returns
// void. Volatile registers (ECX/EDX/EAX) are clobbered exactly as natively; EBX/ESI/EDI/EBP are preserved by the C++ ABI.
//
// Observation: a null probe reads no QPC and runs the walk with no extra work. With a probe each callback is bracketed by two
// QueryPerformanceCounter reads (the callback call only: not the dirty check, the +0x10 increment or the erase) and `probe->end`
// is called right after the callback returned, before any native state is touched again, on the calling thread, without
// allocation or locking. `vtable` is the value read before the callback ([cmd] at that moment, the command class) and is
// what EDX carried into the callback, so a callback that retargets or destroys its command cannot change it. A callback that
// exits by exception (SEH/C++) propagates through Run exactly as natively (no cleanup of Q: iterating/index stay as they are)
// and produces no observation; an exception from the erase/destructors likewise leaves the already delivered observation.
// The probe hooks MUST NOT touch native memory or call back into Run.
//
// Optional private route (census only, Probe::routePrivate != 0): the callback address is read from the live table exactly like
// the native walk ([vtbl+slot] after [cmd], one read, kept as the class identity). Only when that raw value equals
// Probe::routeNative (the relocated native callback) AND probe->begin accepts, the same call (ECX = command, EDX = vtable, no
// stack argument, plain ret) goes to Probe::routePrivate instead, a private copy of routeNative; every other callback runs the
// raw table value untouched. begin runs before the first QPC read and must not read QPC itself; `frame` (the address of the
// dispatching frame's return address) is the same value for begin and end of one callback, deeper (numerically lower) for nested
// walks, so the receiver can tell a scope whose frame was unwound by an exception from a live enclosing one. The private
// callback may call back into native code that runs another Run (reentrancy): begin/end then nest strictly.
namespace kntwr_formation_queue {
using U = uint32_t;

constexpr U kNativeQueueVa = 0x581E80; // preferred-base VA of the native walk (Run's original)
constexpr U kNativeEraseVa = 0x56D990; // preferred-base VA of the native erase (relocate with the image delta)
constexpr U kSlotLast = 4;             // [vtbl+4]: the entry that is last in the count sampled at its iteration start
constexpr U kSlotOther = 8;            // [vtbl+8]: every other entry

// Relocated native 0x56D990: ECX = Q, EDX unused (null), one stack argument (the index), callee pops it, plain EAX.
using EraseFn = U (__fastcall*)(void* queue, void* edx, U index);
// One command callback returned normally: `slot` is kSlotLast or kSlotOther, qpcTicks the QPC delta around the callback only,
// `routed` whether probe->begin accepted it and routePrivate ran in place of the table's callback.
struct Probe {
    U routeNative;    // relocated native callback whose live table value selects the private route (0: never)
    U routePrivate;   // private copy of routeNative with the same ABI; 0 disables routing (begin is then never called)
    bool (*begin)(U vtable, U slot, U frame);
    void (*end)(U vtable, U slot, unsigned long long qpcTicks, bool routed, U frame);
};

// Runs 0x581E80 on Q (= F+0x20). `erase` (non-null) is the relocated 0x56D990; `probe` may be null (no observation, no route).
void Run(void* queue, EraseFn erase, const Probe* probe);
} // namespace kntwr_formation_queue
