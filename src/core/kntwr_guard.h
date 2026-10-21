#ifndef KNTWR_GUARD_H
#define KNTWR_GUARD_H
// Per-thread count of enclosing "expected fault" probes. Every deliberate guarded read of foreign memory
// (__try ... __except(EXCEPTION_EXECUTE_HANDLER) around a possibly dangling pointer) brackets it with ++/-- of this counter, so the
// first-chance crash capture (kntwr_runtime.cpp, CrashVeh) can tell a probe that is about to be caught from a real fault.
// Manual ++/--, not RAII: a function containing __try cannot own objects with destructors under /EHsc.
namespace kntwr {
inline thread_local unsigned probeDepth = 0;
}
#endif
