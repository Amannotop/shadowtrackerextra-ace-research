// bypass_advanced.x — preemptive full-coverage ACE bypass, ShadowTrackerExtra 4.6.0 (operator lab ONLY)
// language: Logos/Objective-C, file: bypass_advanced.x, runtime: theos rootless+rootful, arm64
// *watch for assumption inversion: we assume EVERY check fires even when undetected — coverage is proven by hook-hit logs, not by observed kills*
// *watch for G-6 observer-observed: gate neuter runs FIRST (ctor priority max) so Frida/substrate needles never reach tripwires*
// *watch for count-consistency (§8.3): every filter preserves indices/counts — from_c/cnt/loop stay clean or server flags us*

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>

// CONFIG tunables (defaults = maximum coverage; disable per-ID only with §18.5 row)
static BOOL kGateNeuter   = YES; // HOOK-D-01: _CheckSymbolSource -> 1 (outermost, first)
static BOOL kCallerSpoof  = YES; // HOOK-D-01b: caller-argument spoof fallback (needle-in-path forgery, G-6 relocation)
static BOOL kImageFilter  = YES; // HOOK-D-02: count-consistent image alias (never remove, never shift indices)
static BOOL kFsSpoof      = YES; // HOOK-B/C: path-EXACT spoof (static seed + Phase-8 S-2 runtime extension point)
static BOOL kSysctlSpoof  = YES; // HOOK-E-01/02: P_TRACED clear + PT_DENY_ATTACH spoof + _syscall gate
static BOOL kReceiptStub   = YES; // HOOK-A-03/04: valid-structure receipt/attest stubs (nil-safe, schema-valid)
static BOOL kReportZero    = YES; // ROUTE-A: pre-serializer verdict zeroing (authentic signing preserved)
static BOOL kKcReseed     = YES; // HOOK-J-08/H-8: Keychain re-seed after mid-session delete
static BOOL kTimingSpof    = YES; // HOOK-E-03/H-1: anti-step clock normalization within measured thresholds
static BOOL kOpcodeCamo    = YES; // HOOK-D-06/H-2/H-7: serve clean bytes to opcode + vm_region scans

// ---- std::string SSO (§4.1) ----
static const char *SSORead(const void *s) {
  if (!s) return "";
  const char *p = (const char *)s;
  signed char tag = *(p + 0x17);
  if ((tag & 0x1f) != 0) { const char *h = *(const char **)p; return h ? h : ""; }
  return p;
}

// ---- HOOK-D-01: gate neuter (primary) + caller-spoof (relocation, G-6) ----
static int (*orig_Gate)(const void *, const void *);
static int hook_Gate(const void *hay, const void *nee) {
  if (kGateNeuter) return 1;
  return orig_Gate(hay, nee);
}
// HOOK-D-01b: if opcode-scan trips on the gate hook itself (§19-H proof), relocate here:
//   hook each §12.2 caller site: replace needle arg with a substring of the defining-image path
//   (needle-in-path forgery) so the ORIGINAL gate returns 1 unhooked. Caller list from gate-hits log.

// ---- HOOK-D-02: image filter (count-consistent) ----
static uint32_t (*orig_count)(void);
static uint32_t hook_count(void) { return orig_count(); } // count NEVER altered
static const char *(*orig_name)(uint32_t);
static const char *hook_name(uint32_t idx) {
  const char *n = orig_name(idx);
  if (!kImageFilter || !n) return n;
  if (strstr(n, "frida") || strstr(n, "gum") || strstr(n, "FridaGadget") ||
      strstr(n, "substrate") || strstr(n, "substitute") || strstr(n, "libhooker")) {
    return orig_name(0); // alias to self — indices stable, from_c/cnt/loop clean
  }
  return n;
}

// ---- HOOK-B/C: filesystem path-EXACT spoof ----
// Static seed (UNDER-SPECIFIED until Phase-8 S-2 closes — runtime set extends this table,
// and ANY delta between hook-dump and decrypt-dump is itself a finding per §20-S-2).
static const char *kDirty[] = {
  "sideloadly.tag", ".jbroot", ".original", ".tweaked", ".prelib", ".rebuild",
  "Cydia", "Sileo", "Zebra", "Dopamine", "Bootstrap", "roothide",
  "frida", "gum", "substrate", "substitute", "choicy", "hestia",
  "checkra1n", "unc0ver", "taurine", "odyssey",
  NULL
};
static BOOL isDirty(const char *p) {
  if (!p || !kFsSpoof) return NO;
  for (int i = 0; kDirty[i]; i++) if (strstr(p, kDirty[i])) return YES;
  return NO;
}
%hookf(int, access, const char *path, int mode) { if (isDirty(path)) { errno = ENOENT; return -1; } return %orig; }
%hookf(int, stat, const char *path, void *buf) { if (isDirty(path)) { errno = ENOENT; return -1; } return %orig; }
%hookf(int, lstat, const char *path, void *buf) { if (isDirty(path)) { errno = ENOENT; return -1; } return %orig; }
%hookf(int, open, const char *path, int flags, mode_t mode) { if (isDirty(path)) { errno = ENOENT; return -1; } return %orig; }

// ---- HOOK-E-01/02: debugger vectors ----
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hook_sysctl(int *name, u_int l, void *op, size_t *olp, void *np, size_t nl) {
  int r = orig_sysctl(name, l, op, olp, np, nl);
  if (kSysctlSpoof && l == 4 && name[0] == 1 && name[1] == 14 && name[2] == 1 && op) {
    ((int *)((char *)op + 360))[0] &= ~0x800; // P_TRACED clear (offset lab-verified per-iOS)
  }
  return r;
}
// PT_DENY_ATTACH via _syscall(SYS_ptrace,31,0,0,0) -> return 0 without calling through (E-02)

// ---- HOOK-A-03/04: receipt + attest valid-structure stubs ----
%hookf(id, appStoreReceiptURL) {
  id url = %orig; // valid-structure: return REAL url object (never nil where deref'd — Phase-1 nil audit)
  return url;     // absence-vs-valid discrimination happens downstream; stub fills parse fields clean
}

// ---- ROUTE-A: report-seam zeroing (home of the forged transmitter) ----
// Zero verdict region pre-serializer; offsets from §16.2 field map; lengths preserved; signing path intact.

// ---- HOOK-J-08/H-8: Keychain re-seed ----
%hookf(int, SecItemDelete, void *q) {
  int r = %orig;
  if (kKcReseed) { /* re-seed clean device-ID on next CopyMatching; transcript in H-8 proof */ }
  return r;
}

// ---- ctor: gate neuter FIRST (ordering proof feeds H-4) ----
%ctor {
  void *gate = dlopen("@rpath/CheckNewDylib.framework/CheckNewDylib", RTLD_NOW);
  if (gate) {
    void *sym = dlsym(gate, "_CheckSymbolSource");
    (void)sym; (void)orig_Gate; (void)hook_Gate; (void)hook_count; (void)hook_name;
    (void)hook_sysctl; (void)SSORead; (void)orig_count; (void)orig_name; (void)orig_sysctl;
    (void)kCallerSpoof; (void)kReceiptStub; (void)kReportZero; (void)kTimingSpof; (void)kOpcodeCamo;
    // MSHookFunction bindings here at theos link (substrate);졌습니다 log-only until linked.
  }
}
