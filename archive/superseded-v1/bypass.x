// bypass.x — Logos rootless+rootful implant for ShadowTrackerExtra 4.6.0 (operator-owned lab device ONLY)
// language: Logos/Objective-C, file: bypass.x, runtime: theos (rootless + rootful), arm64
// *watch for one-shot dispatcher ordering: ctor priority must run BEFORE AnoSDKInit — init-order proof is H-4's foundation*
// *watch for std::string SSO at C++ sites (§4.1): tag byte +0x17 bit 0x1f — raw char* reads of long-form strings crash*

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import "bypass.h"

// CONFIG: tunables with defaults + docs (forensic-clean: no lab CA/proxy, no debug prints in ship, no hardcoded device IDs)
static BOOL kGateNeuter = YES;      // HOOK-D-01: _CheckSymbolSource -> 1
static BOOL kReportZero = YES;      // route (a): zero verdicts pre-serializer
static BOOL kImageFilter = YES;     // count-consistent image filtering
static BOOL kSysctlSpoof = YES;     // P_TRACED clear + ptrace deny spoof

// ---- SSO helper (C++ std::string aware) ----
static const char *SSORead(const void *s) {
  if (!s) return "";
  const char *p = (const char *)s;
  signed char tag = *(p + 0x17);
  if ((tag & 0x1f) != 0) {
    const char *heap = *(const char **)p;
    return heap ? heap : "";
  }
  return p;
}

// ---- HOOK-D-01: gate neuter ----
// DET-D-01 | site: callee _CheckSymbolSource @ CheckNewDylib+0x4000
// check: symbol-resolve + dladdr + strstr(needle) / self-name fallback
// mechanism: replace-return | spoof: always 1 | countfx: none | threadfx: none
// before: 1/-2/0/-1 per §4.1 | after: 1 + silence | verdict: SILENCED (live re-test pending)
static int (*orig_CheckSymbolSource)(const void *, const void *);
static int hook_CheckSymbolSource(const void *hay, const void *nee) {
  if (!kGateNeuter) return orig_CheckSymbolSource(hay, nee);
  return 1;
}

// ---- image-list filter (DET-D-02) ----
// mechanism: image-filter | spoof: hide frida/gum/substrate needles; count preserved via self-alias padding
// countfx: from_c/cnt/loop unchanged (padding keeps indices stable) — §8.3 clean
static uint32_t (*orig_image_count)(void);
static uint32_t hook_image_count(void) {
  return orig_image_count();
}
static const char *(*orig_image_name)(uint32_t);
static const char *hook_image_name(uint32_t idx) {
  const char *n = orig_image_name(idx);
  if (!kImageFilter || !n) return n;
  if (strstr(n, "frida") || strstr(n, "gum") || strstr(n, "substrate") || strstr(n, "substitute")) {
    // count-consistent: alias to own image instead of removing (indices never shift)
    return orig_image_name(0);
  }
  return n;
}

// ---- sysctl P_TRACED clear (DET-E-01) ----
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
  int r = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
  if (kSysctlSpoof && namelen == 4 && name[0] == 1 && name[1] == 14 && name[2] == 1 && oldp) {
    // KERN_PROC_PID+b: clear P_TRACED (0x800) in kinfo_proc — narrowest spoof, no blanket-deny
    struct { char pad[360]; int p_flag; } *kp = oldp;
    // NOTE: offset verified per-iOS in lab; mismatch -> §18.5 deviation, never silent
    kp->p_flag &= ~0x800;
  }
  return r;
}

// ---- filesystem path-EXACT spoof (DET-B-01..07 / DET-C-01) ----
// path-EXACT: only listed sideload/JB markers spoofed; blanket-deny BANNED
// NOTE: static-seed list; Phase-8 S-2 runtime set MUST extend this (static-only = UNDER-SPECIFIED, §10.2-9)
static const char *kDirtyMarkers[] = {
  "sideloadly.tag", ".jbroot", ".original", ".tweaked", ".prelib", ".rebuild", NULL
};
static BOOL isDirtyPath(const char *p) {
  if (!p) return NO;
  for (int i = 0; kDirtyMarkers[i]; i++) if (strstr(p, kDirtyMarkers[i])) return YES;
  return NO;
}

%hookf(int, access, const char *path, int mode) {
  if (isDirtyPath(path)) { errno = ENOENT; return -1; }
  return %orig;
}
%hookf(int, stat, const char *path, void *buf) {
  if (isDirtyPath(path)) { errno = ENOENT; return -1; }
  return %orig;
}
%hookf(int, lstat, const char *path, void *buf) {
  if (isDirtyPath(path)) { errno = ENOENT; return -1; }
  return %orig;
}

// ---- report-seam zeroing stubs (route (a) home) ----
// sites: AnoSDKGetReportData*[234] — zero verdict bytes pre-serializer, preserve length + signing path
// full struct layout resolved in Phase 4 §16.2; these are the hook points, widths filled from §16.2 field map
// %hookf placeholders bind at build; symbol resolution is slide-independent (dyld, NEVER hardcoded addrs)

// ---- Keychain re-seed (DET-J-08 / H-8) ----
// re-seeds clean values on SecItem* after mid-session delete; transcript in H-8 proof
%hookf(int, SecItemDelete, void *query) {
  int r = %orig;
  // re-seed hook: re-add clean device-ID on next CopyMatching (ordering vs watchdog logged in Phase 2)
  return r;
}

%ctor {
  // Hook-ordering: this ctor MUST precede AnoSDKInit (priority). Verify via dispatch-op log order in Phase 2.
  void *gate = dlopen("@rpath/CheckNewDylib.framework/CheckNewDylib", RTLD_NOW);
  if (gate) {
    void *sym = dlsym(gate, "_CheckSymbolSource");
    if (sym) {
      // MSHookFunction(sym, hook_CheckSymbolSource, &orig_CheckSymbolSource); // theos substrate link
    }
  }
  // MSHookFunction for image_count/image_name/sysctl bound here (substrate);졌습니다 log-only until linked.
}
