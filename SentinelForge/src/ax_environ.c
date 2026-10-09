// ax_environ.c — env-delta rows: each is comparable across A/B runs
#include "ax_environ.h"
#include <string.h>
#include <stdio.h>
static int has_raw(const ax_image_t *img, const char *s) {
  size_t nl = strlen(s), lim = img->img_len < 8000000 ? img->img_len : 8000000;
  for (size_t k = 0; k + nl < lim; k++)
    if (!memcmp(img->img + k, s, nl)) return 1;
  return 0;
}
int ax_environ_analyze(const ax_image_t *img, const char *app_dir, ax_db_t *db) {
  int n = 0;
  // device-id inputs (feed payload fingerprint fields — differ per install/device)
  const char *ids[][2] = {
    {"identifierForVendor", "IDFV (per-vendor, resets on reinstall)"},
    {"advertisingIdentifier", "IDFA (consent-gated)"},
    {"CFUUIDCreate", "CFUUID (derivation+persistence? Keychain/file?)"},
    {"UIDevice", "UIDevice queries (model/systemVersion/name)"},
    {"utsname", "uname (machine string — Mac vs iPhone is THE delta)"},
    {"sysctlbyname", "hw.* queries (hw.machine/hw.model — platform tell)"},
    {"hw.machine", "machine literal"}, {"iPhone", "iPhone literal (vs Mac*)"},
    {"ProcessInfo", "NSProcessInfo (environment/osVersion)"},
    {"NSUserDefaults", "defaults (persistence surface)"},
    {"UIPasteboard", "pasteboard (cross-app/token channel?)"},
    {"CTTelephony", "carrier info"}, {"CTCarrier", "carrier"},
    {"Locale", "locale"}, {"TimeZone", "timezone"}, {"currentLocale", "locale query"},
    {"isJailbroken", "jb predicate"}, {"jailbreak", "jb literal"},
    {"DYLD_INSERT_LIBRARIES", "insertion env (set = injected)"},
    {"HOME", "env HOME (container path tells)"}, {"TMPDIR", "env TMPDIR (container tells)"},
    {"CFNetworkCopySystemProxySettings", "proxy settings (mitmproxy visibility)"},
    {"SCNetworkReachability", "reachability"},
    {"getenv", "env-var reads (which vars? enumerate callers)"},
    {"NSFileManager", "file-manager probes"}, {"defaultManager", "file probes"},
    {"contentsOfDirectory", "dir listing (bundle/container walk?)"},
    {"Ubiquity", "icloud (account linkage?)"},
    {NULL, NULL}
  };
  for (int i = 0; ids[i][0]; i++) {
    if (has_raw(img, ids[i][0])) {
      char t[200], e[480];
      snprintf(t, sizeof(t), "env-delta %s", ids[i][0]);
      snprintf(e, sizeof(e), "%s — record value on env-A vs env-B; delta feeds payload fingerprint or branch", ids[i][1]);
      ax_conf_t c = (!strcmp(ids[i][0], "utsname") || !strcmp(ids[i][0], "hw.machine") ||
                     !strcmp(ids[i][0], "DYLD_INSERT_LIBRARIES") || !strcmp(ids[i][0], "isJailbroken"))
        ? AX_HIGH : AX_LOW;
      ax_db_add(db, AXCAT_ENV, c, "environ", t, e, 0, c == AX_HIGH ? 2 : 1);
      n++;
    }
  }
  // container/sandbox tells
  {
    char e[480];
    snprintf(e, sizeof(e), "app_dir=%s (container UUID, Mobile vs macOS paths, /X/ scratch dirs — snapshot per run, diff A/B)", app_dir);
    ax_db_add(db, AXCAT_ENV, AX_MED, "environ", "container-snapshot", e, 0, 1);
    n++;
  }
  return n;
}
