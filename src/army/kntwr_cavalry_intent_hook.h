// Cavalry attack-intent flush entry hook: the generic queue flush 0x542AE0 (contract: local://cavalry-retained-intent-contract.md,
// #Native authority). The observer must never dereference native memory; it only feeds kntwr_cavalry::ObserveFlush(ring) the
// ECX the native entry received (U+0x390). Install only at activation with a bound adapter; Remove before state teardown or
// unload, and a failed Remove must retain the adapter state and the module (the gate stays reachable until it succeeds).
#ifndef KNTWR_CAVALRY_INTENT_HOOK_H
#define KNTWR_CAVALRY_INTENT_HOOK_H
#include <stdint.h>

namespace kntwr_cavalry_intent_hook {
using U = uint32_t;

// `imageBase` is the runtime load base of Napoleon.exe (the runtime's `imageBase`, NOT its `delta`):
// site = imageBase - 0x400000 + 0x542AE0. True only while the 8-byte patch is in place.
bool Install(U imageBase);
bool Remove();
bool Installed();
} // namespace kntwr_cavalry_intent_hook
#endif
