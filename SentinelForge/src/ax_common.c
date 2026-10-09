// ax_common.c — finding store + logging
#include "ax_common.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static int g_verbose = 1;
void ax_set_verbose(int v) { g_verbose = v; }
void ax_log(int level, const char *fmt, ...) {
  if (level > g_verbose) return;
  va_list ap; va_start(ap, fmt);
  fprintf(stderr, "[axe] ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}
void ax_db_add(ax_db_t *db, ax_cat_t cat, ax_conf_t conf, const char *stage,
  const char *title, const char *evidence, uint64_t vaddr, int signals) {
  if (!db || db->count >= AX_MAX_FINDINGS) return;
  ax_finding_t *f = &db->items[db->count++];
  snprintf(f->id, sizeof(f->id), "AX-%04d", ++db->seq);
  f->cat = cat; f->conf = conf; f->vaddr = vaddr; f->signals = signals;
  snprintf(f->stage, sizeof(f->stage), "%.23s", stage ? stage : "?");
  snprintf(f->title, sizeof(f->title), "%.159s", title ? title : "");
  snprintf(f->evidence, sizeof(f->evidence), "%.767s", evidence ? evidence : "");
  f->refs[0] = 0;
}
const char *ax_cat_name(ax_cat_t c) {
  static const char *n[] = {"debug","jailbreak","dylib","signature","network","keychain",
    "mach","report","crypto","thread","environment","codesign","receipt","misc"};
  return (c >= 0 && c <= AXCAT_MISC) ? n[c] : "misc";
}
const char *ax_conf_name(ax_conf_t c) {
  return c == AX_CONFIRMED ? "CONFIRMED" : c == AX_HIGH ? "HIGH" : c == AX_MED ? "MED" : "LOW";
}
