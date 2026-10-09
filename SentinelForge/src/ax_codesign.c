// ax_codesign.c — bundle forensics: plist fields, provision, CodeResources coverage,
// sideload artifacts, LC cryptid. Every row is diffable across environments.
#include "ax_codesign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
static int fexists(const char *p) { struct stat st; return !stat(p, &st); }
static long fsize(const char *p) { struct stat st; return stat(p, &st) ? -1 : (long)st.st_size; }
// minimal plist string grabber: <key>K</key> ... <string>V</string>
static int plist_string(const char *plist, const char *key, char *out, size_t cap) {
  FILE *f = fopen(plist, "rb");
  if (!f) return -1;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n <= 0 || n > 2000000) { fclose(f); return -1; }
  char *b = malloc(n + 1);
  if (fread(b, 1, n, f) != (size_t)n) { free(b); fclose(f); return -1; }
  b[n] = 0; fclose(f);
  char pat[160];
  snprintf(pat, sizeof(pat), "<key>%s</key>", key);
  char *k = strstr(b, pat);
  int r = -1;
  if (k) {
    char *s = strstr(k, "<string>");
    if (s && s - b < n) {
      s += 8;
      char *e = strstr(s, "</string>");
      if (e) {
        size_t L = (size_t)(e - s);
        if (L >= cap) L = cap - 1;
        memcpy(out, s, L); out[L] = 0; r = 0;
      }
    }
  }
  free(b);
  return r;
}
static void file_row(ax_db_t *db, const char *app, const char *rel, const char *role) {
  char p[1024];
  snprintf(p, sizeof(p), "%s/%s", app, rel);
  long sz = fsize(p);
  char t[256], e[512];
  snprintf(t, sizeof(t), "bundle-artifact %s", rel);
  if (sz < 0) snprintf(e, sizeof(e), "ABSENT (%s)", role);
  else snprintf(e, sizeof(e), "present, %ld B (%s)", sz, role);
  // sideload markers promote confidence (they ARE the env difference)
  ax_conf_t c = AX_LOW;
  if (!strcmp(rel, "sideloadly.tag") || !strcmp(rel, ".jbroot") || !strcmp(rel, ".prelib") ||
      !strcmp(rel, ".rebuild") || !strcmp(rel, ".tweaked") || !strcmp(rel, ".original"))
    c = sz < 0 ? AX_LOW : AX_HIGH;
  ax_db_add(db, AXCAT_CODEIGN, c, "codesign", t, e, 0, sz < 0 ? 1 : 2);
}
int ax_codesign_analyze(const char *app_dir, const char *main_binary_path, ax_db_t *db) {
  int n = 0;
  char plist[1024], prov[1024], cr[1024];
  snprintf(plist, sizeof(plist), "%s/Info.plist", app_dir);
  snprintf(prov, sizeof(prov), "%s/embedded.mobileprovision", app_dir);
  snprintf(cr, sizeof(cr), "%s/_CodeSignature/CodeResources", app_dir);
  const char *keys[] = {"CFBundleIdentifier","CFBundleExecutable","CFBundleShortVersionString",
    "CFBundleName","CFBundleDisplayName","CFBundlePackageType",NULL};
  char row[1024] = "";
  for (int i = 0; keys[i]; i++) {
    char v[192] = "";
    if (!plist_string(plist, keys[i], v, sizeof(v))) {
      char t[256], e[512];
      snprintf(t, sizeof(t), "bundle-id %s=%s", keys[i], v);
      // dev-suffixed identifiers (e.g. .Q798597U2K) + non-Apple team = sideload evidence
      ax_conf_t c = AX_LOW;
      if ((!strcmp(keys[i], "CFBundleIdentifier")) && (strchr(v, '.') && strlen(v) > 24)) c = AX_MED;
      snprintf(e, sizeof(e), "Info.plist %s (diff vs App Store baseline: suffix/team drift = sideload)", keys[i]);
      ax_db_add(db, AXCAT_CODEIGN, c, "codesign", t, e, 0, 1);
      n++;
      strncat(row, v, sizeof(row) - strlen(row) - 2);
      strncat(row, "|", sizeof(row) - strlen(row) - 1);
    }
  }
  // URL schemes (ACE canOpenURL probes of OTHER apps' schemes — enumerate fully)
  {
    FILE *f = fopen(plist, "rb");
    if (f) {
      fseek(f, 0, SEEK_END);
      long sz = ftell(f);
      fseek(f, 0, SEEK_SET);
      if (sz > 0 && sz < 2000000) {
        char *b = malloc(sz + 1);
        if (fread(b, 1, sz, f) == (size_t)sz) {
          b[sz] = 0;
          // crude: collect CFBundleURLSchemes string entries
          int ns = 0;
          char *p = b;
          while ((p = strstr(p, "<string>")) && ns < 32) {
            p += 8;
            char *e = strstr(p, "</string>");
            if (!e) break;
            // only keep scheme-looking values near URL context (heuristic: short, alnum+-)
            size_t L = (size_t)(e - p);
            if (L > 3 && L < 64) {
              char v[72];
              memcpy(v, p, L); v[L] = 0;
              int ok = 1;
              for (size_t k = 0; k < L; k++)
                if (!((v[k] >= 'a' && v[k] <= 'z') || (v[k] >= 'A' && v[k] <= 'Z') ||
                      (v[k] >= '0' && v[k] <= '9') || v[k] == '-' || v[k] == '.' || v[k] == '_' || v[k] == '+')) { ok = 0; break; }
              if (ok && (strstr(v, "fb") == v || strstr(v, "twitter") || strchr(v, ':') == NULL)) {
                // keep conservative: only obvious scheme ids
                if (!strncmp(v, "fb", 2) || strstr(v, "twitterkit") || strstr(v, "://") == NULL) {
                  char t[160], ev[320];
                  snprintf(t, sizeof(t), "url-scheme %s", v);
                  snprintf(ev, sizeof(ev), "CFBundleURLSchemes entry (ACE relevance: canOpenURL probes of OTHER apps' schemes)");
                  ax_db_add(db, AXCAT_JB, AX_LOW, "codesign", t, ev, 0, 1);
                  n++; ns++;
                }
              }
            }
            p = e + 9;
          }
          (void)ns;
        }
        free(b);
      }
      fclose(f);
    }
  }
  // provisioning
  {
    long sz = fsize(prov);
    char t[160], e[512];
    if (sz < 0) {
      snprintf(t, sizeof(t), "provisioning ABSENT");
      snprintf(e, sizeof(e), "no embedded.mobileprovision (App Store builds carry store provision; absence/drift = env delta)");
      ax_db_add(db, AXCAT_CODEIGN, AX_MED, "codesign", t, e, 0, 1);
    } else {
      snprintf(t, sizeof(t), "provisioning present %ld B", sz);
      snprintf(e, sizeof(e), "embedded.mobileprovision present — parse team/app-id/entitlements for dev-vs-store discrimination (KEY env delta)");
      ax_db_add(db, AXCAT_CODEIGN, AX_HIGH, "codesign", t, e, 0, 2);
    }
    n++;
  }
  // CodeResources coverage
  {
    long sz = fsize(cr);
    char e[512];
    snprintf(e, sizeof(e), "%s (coverage decides hide-vs-delete per artifact; parse resource rules)",
      sz < 0 ? "CodeResources ABSENT (unsigned/adhoc?)" : "CodeResources present");
    ax_db_add(db, AXCAT_CODEIGN, sz < 0 ? AX_HIGH : AX_MED, "codesign", "codesignature-cover", e, 0, 2);
    n++;
  }
  // sideload artifacts (ALL verdicts, present or absent — absence is evidence too)
  const char *arts[][2] = {
    {"sideloadly.tag","sideload injector tag"}, {".jbroot","rootless marker"},
    {".original","pre-patch image"}, {".tweaked","live patched image"},
    {".prelib","injector stub (reverse entry/purpose)"}, {".rebuild","toolchain metadata"},
    {"SC_Info","store receipt dir"}, {"ue4commandline.txt","engine flags (codepath switches)"},
    {"Manifest_NonUFSFiles_IOS.txt","manifest-vs-disk drift input"}, {"embedded.mobileprovision","dev profile"},
    {NULL, NULL}
  };
  for (int i = 0; arts[i][0]; i++) { file_row(db, app_dir, arts[i][0], arts[i][1]); n++; }
  // main binary cryptid (LC_ENCRYPTION_INFO_64 cryptid==0 => decrypted/analyzable)
  {
    FILE *f = fopen(main_binary_path, "rb");
    if (f) {
      uint8_t hdr[4096];
      size_t r = fread(hdr, 1, sizeof(hdr), f);
      fclose(f);
      if (r == sizeof(hdr)) {
        // find cryptid heuristic: search LC (cmd 0x2c/0x2d) — simplified: report via otool delegation note
        ax_db_add(db, AXCAT_CODEIGN, AX_LOW, "codesign", "cryptid-check",
          "LC_ENCRYPTION_INFO_64 cryptid: verify via LC walk (0=decrypted, direct analysis OK)", 0, 1);
        n++;
      }
    }
  }
  return n;
}
