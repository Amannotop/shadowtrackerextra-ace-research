// ax_imports.c — API table with roles; dylib heuristics distinguish system vs third-party
#include "ax_imports.h"
#include <string.h>
#include <stdio.h>
typedef struct { const char *sub; ax_cat_t cat; const char *role; } api_t;
// Role strings explain WHY the API matters for environment-differential analysis.
static api_t gAPIs[] = {
  {"access",AXCAT_JB,"path probe (sideload/JB markers)"}, {"stat",AXCAT_JB,"path probe"},
  {"lstat",AXCAT_JB,"path probe"}, {"fstat",AXCAT_JB,"fd probe"}, {"statfs",AXCAT_JB,"fs probe"},
  {"open",AXCAT_JB,"path open"}, {"openat",AXCAT_JB,"path open"}, {"opendir",AXCAT_JB,"dir probe"},
  {"readdir",AXCAT_JB,"dir probe"}, {"readlink",AXCAT_JB,"link probe"}, {"mmap",AXCAT_JB,"blob map"},
  {"getattrlist",AXCAT_JB,"attr probe"}, {"sysctl",AXCAT_DEBUG,"P_TRACED/debugger"},
  {"sysctlbyname",AXCAT_DEBUG,"debugger"}, {"syscall",AXCAT_DEBUG,"ptrace gate"},
  {"ptrace",AXCAT_DEBUG,"deny-attach"}, {"fork",AXCAT_DEBUG,"escape/sandbox"},
  {"dlopen",AXCAT_DYLIB,"load monitor"}, {"dlsym",AXCAT_DYLIB,"symbol resolve"},
  {"dladdr",AXCAT_DYLIB,"image provenance"}, {"dlclose",AXCAT_DYLIB,"load monitor"},
  {"__dyld_image_count",AXCAT_DYLIB,"image enumeration"}, {"__dyld_get_image_name",AXCAT_DYLIB,"image enumeration"},
  {"__dyld_get_image_header",AXCAT_DYLIB,"image enumeration"}, {"__dyld_get_image_vmaddr_slide",AXCAT_DYLIB,"ASLR slide"},
  {"connect",AXCAT_NET,"transport"}, {"socket",AXCAT_NET,"transport"}, {"getaddrinfo",AXCAT_NET,"dns"},
  {"CFNetworkCopySystemProxySettings",AXCAT_NET,"proxy visibility (mitmproxy relevance)"},
  {"SCNetworkReachability",AXCAT_NET,"reachability"},
  {"SecItemAdd",AXCAT_KC,"keychain write"}, {"SecItemCopyMatching",AXCAT_KC,"keychain read"},
  {"SecItemDelete",AXCAT_KC,"keychain delete"},
  {"mach_absolute_time",AXCAT_MACH,"anti-step clock"}, {"mach_timebase_info",AXCAT_MACH,"clock"},
  {"mach_msg",AXCAT_MACH,"ipc/exception-port"}, {"mach_task_self_",AXCAT_MACH,"task port"},
  {"mach_port_deallocate",AXCAT_MACH,"port rights"}, {"mach_vm_region",AXCAT_MACH,"region scan"},
  {"mach_vm_remap",AXCAT_MACH,"unpack/mutate"}, {"pid_for_task",AXCAT_MACH,"anti-attach"},
  {"task_get_special_port",AXCAT_MACH,"exception port"}, {"task_info",AXCAT_MACH,"task inspect"},
  {"exit",AXCAT_REPORT,"local kill"}, {"kill",AXCAT_REPORT,"local kill"}, {"abort",AXCAT_REPORT,"local kill"},
  {"pthread_create",AXCAT_THREAD,"watchdog spawn"}, {"pthread_getname_np",AXCAT_THREAD,"thread census"},
  {"dispatch_",AXCAT_THREAD,"queue/timer"}, {"CFUUIDCreate",AXCAT_ENV,"device-id input"},
  {"identifierForVendor",AXCAT_ENV,"device id"}, {"advertisingIdentifier",AXCAT_ENV,"ad id"},
  {"isJailbroken",AXCAT_JB,"jb predicate"}, {"canOpenURL",AXCAT_JB,"scheme probe"},
  {"appStoreReceiptURL",AXCAT_RECEIPT,"receipt anchor"}, {"attestKey",AXCAT_SIG,"appattest"},
  {"inflate",AXCAT_CRYPTO,"packed tables"}, {"CC_",AXCAT_CRYPTO,"commoncrypto"}, {"SecKey",AXCAT_CRYPTO,"asymmetric"},
  {NULL,0,NULL}
};
// raw-name fallback for stripped binaries: bounded memmem over first 8MB
static int raw_has(const ax_image_t *img, const char *needle) {
  size_t nl = strlen(needle);
  size_t lim = img->img_len < 8000000 ? img->img_len : 8000000;
  if (nl < 3 || lim <= nl) return 0;
  for (size_t k = 0; k + nl < lim; k++)
    if (!memcmp(img->img + k, needle, nl)) return 1;
  return 0;
}
int ax_imports_inventory(const ax_image_t *img, const ax_symtab_t *sym, ax_db_t *db) {
  int found = 0, total = 0;
  for (api_t *a = gAPIs; a->sub; a++) {
    total++;
    int hit = 0;
    const char *src = "symtab";
    for (int i = 0; i < sym->n; i++)
      if (strstr(sym->v[i].name, a->sub)) { hit = 1; break; }
    if (!hit && raw_has(img, a->sub)) { hit = 1; src = "raw-name"; }
    if (hit) {
      char t[160], e[320];
      snprintf(t, sizeof(t), "api %s", a->sub);
      snprintf(e, sizeof(e), "role=%s (evidence: %s presence)", a->role, src);
      // symtab evidence = HIGH-ish (MED cap pre-correlation); raw-name = LOW-MED
      ax_db_add(db, a->cat, !strcmp(src, "symtab") ? AX_MED : AX_LOW, "imports", t, e, 0, !strcmp(src, "symtab") ? 2 : 1);
      found++;
    }
  }
  char ev[160];
  snprintf(ev, sizeof(ev), "security-api hits=%d/%d (symtab preferred, raw-name fallback labeled)", found, total);
  ax_db_add(db, AXCAT_MISC, AX_HIGH, "imports", "api-inventory", ev, 0, 2);
  return found;
}
int ax_dylibs_analyze(const ax_image_t *img, ax_db_t *db) {
  int third = 0;
  for (int i = 0; i < img->ndyl; i++) {
    const char *d = img->dylibs[i];
    int is_sys = !strncmp(d, "/System/", 8) || !strncmp(d, "/usr/lib", 8);
    int is_rpath = !strncmp(d, "@rpath", 6) || !strncmp(d, "@executable_path", 17) || !strncmp(d, "@loader_path", 12);
    if (is_sys) continue;
    char t[200], e[400];
    if (is_rpath) {
      const char *sl = strrchr(d, '/');
      snprintf(t, sizeof(t), "bundled-dylib %s", sl ? sl + 1 : d);
      snprintf(e, sizeof(e), "bundled %s — enumerate exports/imports separately; image-count loops see it (count-consistency applies)", d);
      ax_db_add(db, AXCAT_DYLIB, AX_MED, "dylibs", t, e, 0, 1);
    } else {
      snprintf(t, sizeof(t), "third-party-dylib %s", d);
      snprintf(e, sizeof(e), "non-system, non-bundled load path: unexpected module surface (injected? repackaged?) — verify signature + LC_LOAD origin", d);
      ax_db_add(db, AXCAT_DYLIB, AX_HIGH, "dylibs", t, e, 0, 2);
      third++;
    }
  }
  // well-known ACE/reporting frameworks by name (bundled but security-relevant)
  for (int i = 0; i < img->ndyl; i++) {
    const char *d = img->dylibs[i];
    if (strstr(d, "anogs") || strstr(d, "CheckNewDylib") || strstr(d, "CrashKit") || strstr(d, "CrashSight") || strstr(d, "CydiaSubstrate")) {
      char t[200], e[400];
      snprintf(t, sizeof(t), "security-framework %s", strrchr(d, '/') ? strrchr(d, '/') + 1 : d);
      snprintf(e, sizeof(e), "%s — treat as detection surface: map its exports/imports/threads (Phase-0 triage, never silent-omitted)", d);
      ax_db_add(db, AXCAT_DYLIB, AX_HIGH, "dylibs", t, e, 0, 2);
    }
  }
  if (!third) ax_db_add(db, AXCAT_DYLIB, AX_LOW, "dylibs", "no-third-party-dylibs", "all linked libraries are system or @rpath-bundled (absence is also evidence)", 0, 1);
  return third;
}
