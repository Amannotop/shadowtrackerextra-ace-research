// version_manager.h — multi-version ACE bypass core (operator lab ONLY)
// language: Objective-C, file: version_manager.h, runtime: theos, arm64
// *watch for update drift: every game update re-slides offsets — NOTHING hardcoded except per-version table rows verified by pattern-scan*
/* DESIGN — why this survives updates:
   1. Fingerprint, don't assume: each supported version is identified by (CFBundleShortVersionString +
      anogs __TEXT hash + export count). Unknown fingerprint = safe-disable + log, NEVER blind-hook.
   2. Pattern-scan, don't hardcode: every hook site resolves via byte-pattern + export-name double-check.
      If pattern fails AND export missing -> that hook reports UNSUPPORTED for this version, rest stay armed.
   3. Config-per-version: offsets, dispatcher opcodes, struct layouts, magic constants live in one table
      row per version. Adding a version = adding a row + running the verifier. No code changes.
   4. Graceful degradation: per-hook status (ARMED / UNSUPPORTED / FAILED) is queryable at runtime and
      written to the coverage log — a half-supported version is explicit, never silent. */
#ifndef VERSION_MANAGER_H
#define VERSION_MANAGER_H
#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, HookStatus) { HookARMED, HookUNSUPPORTED, HookFAILED };

typedef struct {
  const char *version;        // e.g. "4.6.0"
  const char *anogsSHA256;    // __TEXT hash — fingerprint anchor
  int exportCount;            // expected AnoSDK T count (19 on 4.6.0)
  // hook sites (file offsets — re-verified by pattern at load; mismatch = FAILED, never blind-fire)
  unsigned long gateOff;      // _CheckSymbolSource (0x4000 on 4.6.0)
  unsigned long dispatchOff;  // central dispatcher (0x376a0 on 4.6.0)
  unsigned long ioctlOff;     // obfuscated dispatcher (0x26398 on 4.6.0)
  unsigned long seamOffs[17]; // AnoSDK export offsets in SEAM order
  int dispatchOpcodes;        // opcode ceiling (6 on 4.6.0)
  const char *notes;          // drift notes (§18.5 chain)
} VersionRow;

// Supported table — APPEND rows, never edit verified rows in place (history is evidence)
static const VersionRow kVersions[] = {
  {
    "4.6.0", "5c8dae8b156c8d2316f41680b36c650336a1809600d2d08a1c1e130e78508d49",
    19,
    0x4000, 0x376a0, 0x26398,
    {0xf0fd0,0xf0ffc,0xf1000,0xf104c,0xf109c,0xf10bc,0xf1114,0xf1188,0xf10dc,0xf1174,0xf1178,0xf1180,0xf10f8,0xf116c,0xf1168,0xf118c,0xf1170},
    6, "baseline: gate bytes verified, dispatcher mapped, Ioctl OPAQUE-01"
  },
  {
    "4.6.0-kr", "3186d4f32ba83afbcca091485fc49bd7cc7d11fa1a3de2b308ce48adbde064db",
    19,
    0x4000, 0x376a0, 0x26398,
    {0xf0fd0,0xf0ffc,0xf1000,0xf104c,0xf109c,0xf10bc,0xf1114,0xf1188,0xf10dc,0xf1174,0xf1178,0xf1180,0xf10f8,0xf116c,0xf1168,0xf118c,0xf1170},
    6, "KR region (com.pubg.krmobile.Q798597U2K): seam+gate identical to baseline; main 183MB vs 164MB (region content delta); hook table shared"
  },
  // NEXT: {"4.6.1", "<sha>", 19?, ...} — fill by running version_probe.py on the new bundle, then verifier.
};

// API
const VersionRow *VMIdentify(void);                 // fingerprint current bundle -> row or NULL (safe-disable)
HookStatus VMVerifySite(const VersionRow *v, unsigned long off, const unsigned char *pattern, unsigned len);
void VMReportStatus(void);                          // write per-hook ARMED/UNSUPPORTED/FAILED to coverage log

#endif
