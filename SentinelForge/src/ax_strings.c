#include <stdio.h>
// ax_strings.c — weighted patterns; why-strings document significance per pattern
#include "ax_strings.h"
#include <stdlib.h>
#include <string.h>
typedef struct { const char *pat; int w; ax_cat_t cat; const char *why; } pat_t;
// Weights: >=30 strong indicator, 15-25 supporting, <15 context only.
static pat_t gP[] = {
  {"tdm_report",30,AXCAT_REPORT,"report key — exfil field/class"}, {"shell_report",30,AXCAT_REPORT,"report key"},
  {"COREREPORT",30,AXCAT_REPORT,"report key"}, {"cheat_open_id",35,AXCAT_REPORT,"identity key in payload"},
  {"check_state",25,AXCAT_REPORT,"verdict key"}, {"DoRiskFileTCJTask",35,AXCAT_JB,"file-probe oracle format"},
  {"jailbreak",25,AXCAT_JB,"jb literal"}, {"sideloadly",20,AXCAT_SIG,"sideload marker"},
  {".jbroot",20,AXCAT_SIG,"sideload marker"}, {".original",15,AXCAT_SIG,"sideload artifact"},
  {".tweaked",15,AXCAT_SIG,"sideload artifact"}, {".prelib",15,AXCAT_SIG,"injector stub"},
  {"frida",30,AXCAT_DYLIB,"tool literal — paired with image/symbol probes?"}, {"gum",20,AXCAT_DYLIB,"tool literal (FP: argument-)"},
  {"substrate",30,AXCAT_DYLIB,"tool literal"}, {"substitute",25,AXCAT_DYLIB,"tool literal"},
  {"cydia",25,AXCAT_DYLIB,"tool literal (FP: game-bundled frameworks!)"}, {"sileo",20,AXCAT_DYLIB,"tool literal"},
  {"zebra",15,AXCAT_DYLIB,"tool literal"}, {"choicy",20,AXCAT_DYLIB,"tool literal"}, {"hestia",20,AXCAT_DYLIB,"tool literal"},
  {"shadowed",20,AXCAT_DYLIB,"self-detect candidate"}, {"ms_hook_opcode",35,AXCAT_DYLIB,"opcode scanner export"},
  {"inline_hook_opcode",35,AXCAT_DYLIB,"opcode scanner"}, {"set_inline_hook_error",25,AXCAT_DYLIB,"hook-error path"},
  {"attestKey",30,AXCAT_SIG,"DeviceCheck/AppAttest selector"}, {"appStoreReceiptURL",30,AXCAT_SIG,"receipt anchor"},
  {"canOpenURL",20,AXCAT_JB,"scheme probe selector"}, {"DYLD_",20,AXCAT_DYLIB,"env-var check"},
  {"ptrace",25,AXCAT_DEBUG,"debugger API"}, {"P_TRACED",25,AXCAT_DEBUG,"traced flag"},
  {"sysctl",15,AXCAT_DEBUG,"introspection API"}, {"SecItem",15,AXCAT_KC,"keychain API"},
  {"mach_vm_region",20,AXCAT_MACH,"region-scan API"}, {"mach_absolute_time",15,AXCAT_MACH,"timing clock"},
  {"HBCheck",20,AXCAT_REPORT,"heartbeat marker"}, {"heartbeat",20,AXCAT_REPORT,"heartbeat"},
  {"verify",10,AXCAT_SIG,"verify path"}, {"integrity",15,AXCAT_SIG,"integrity path"}, {"tamper",20,AXCAT_SIG,"tamper path"},
  {"attest",25,AXCAT_SIG,"attestation"}, {"receipt",20,AXCAT_SIG,"receipt path"}, {"provision",20,AXCAT_SIG,"profile path"},
  {"entitlement",20,AXCAT_CODEIGN,"entitlement check"}, {"codesign",20,AXCAT_CODEIGN,"signing check"},
  {"TeamIdentifier",20,AXCAT_CODEIGN,"team check"}, {"https://",25,AXCAT_NET,"endpoint"}, {"http://",25,AXCAT_NET,"endpoint"},
  {"/var/",15,AXCAT_JB,"abs-path probe (FP: benign paths!)"}, {"/private/",15,AXCAT_JB,"abs-path probe"},
  {"sem_",10,AXCAT_THREAD,"sync primitive"}, {"ace_worker",20,AXCAT_THREAD,"ACE thread"}, {"ace_schedule",20,AXCAT_THREAD,"ACE scheduler"},
  {"TDM-report",20,AXCAT_REPORT,"TDM thread"}, {"cheat",15,AXCAT_REPORT,"cheat literal"}, {"ban",15,AXCAT_REPORT,"ban literal"},
  {"tcj_",10,AXCAT_CRYPTO,"tcj family"}, {"encrypt",15,AXCAT_CRYPTO,"crypto op"}, {"decrypt",15,AXCAT_CRYPTO,"crypto op"},
  {"nonce",20,AXCAT_CRYPTO,"replay armor"}, {"hmac",20,AXCAT_CRYPTO,"mac op"}, {"md5",10,AXCAT_CRYPTO,"hash op"}, {"sha",10,AXCAT_CRYPTO,"hash op"},
  {"identifierForVendor",20,AXCAT_ENV,"device id API"}, {"advertisingIdentifier",15,AXCAT_ENV,"ad id API"},
  {"isJailbroken",25,AXCAT_JB,"jb predicate"}, {"fork",15,AXCAT_DEBUG,"sandbox-escape API"}, {"exec",10,AXCAT_DEBUG,"exec API"},
  {NULL,0,0,NULL}
};
int ax_strings_scan(const ax_image_t *img, ax_strings_t *out, ax_db_t *db) {
  memset(out, 0, sizeof(*out));
  const uint8_t *p = img->img;
  size_t n = img->img_len, i = 0, cap = 0;
  char buf[256];
  size_t bl = 0, start = 0;
  long total = 0;
  out->v = NULL;
  while (i < n) {
    unsigned char c = p[i];
    if (c >= 32 && c < 127) {
      if (!bl) start = i;
      if (bl < sizeof(buf) - 1) buf[bl++] = c;
    } else {
      if (bl >= 4) {
        buf[bl] = 0; total++;
        int sc = 0, bw = 0;
        ax_cat_t bc = AXCAT_MISC;
        const char *why = "";
        for (pat_t *q = gP; q->pat; q++)
          if (strstr(buf, q->pat)) {
            sc += q->w;
            if (q->w > bw) { bw = q->w; bc = q->cat; why = q->why; }
          }
        if (sc > 0) {
          if (out->n >= (int)cap) {
            cap = cap ? cap * 2 : 1024;
            out->v = realloc(out->v, cap * sizeof(ax_hit_t));
          }
          ax_hit_t *h = &out->v[out->n++];
          size_t L = bl > 199 ? 199 : bl;
          memcpy(h->text, buf, L); h->text[L] = 0;
          h->foff = start;
          h->vaddr = ax_macho_off_to_va(img, start);
          h->score = sc; h->cat = bc;
          snprintf(h->why, sizeof(h->why), "%.95s", why);
        }
      }
      bl = 0;
    }
    i++;
  }
  out->total = total;
  char ev[192];
  snprintf(ev, sizeof(ev), "printable census=%ld scored=%d (string-only: capped at MED until xref/caller/branch/report agree)", total, out->n);
  ax_db_add(db, AXCAT_MISC, AX_HIGH, "strings", "string-census", ev, 0, 2);
  // top-60 as MED findings (promotion happens in correlate/)
  int shown = 0;
  int *used = calloc(out->n ? out->n : 1, sizeof(int));
  while (shown < 60) {
    int bi = -1, bs = 29;
    for (int j = 0; j < out->n; j++)
      if (!used[j] && out->v[j].score > bs) { bs = out->v[j].score; bi = j; }
    if (bi < 0) break;
    used[bi] = 1;
    char t[220], e[560];
    snprintf(t, sizeof(t), "indicator '%s'", out->v[bi].text);
    snprintf(e, sizeof(e), "score=%d cat=%s why=%s fileoff=0x%llx va=0x%llx (NEEDS xref+caller+branch agreement for HIGH)",
      out->v[bi].score, ax_cat_name(out->v[bi].cat), out->v[bi].why,
      (unsigned long long)out->v[bi].foff, (unsigned long long)out->v[bi].vaddr);
    ax_db_add(db, out->v[bi].cat, AX_MED, "strings", t, e, out->v[bi].vaddr, 1);
    shown++;
  }
  free(used);
  return 0;
}
void ax_strings_free(ax_strings_t *s) { free(s->v); memset(s, 0, sizeof(*s)); }
