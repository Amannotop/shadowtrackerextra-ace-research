// ax_diff.c — delta keys + explanatory ranking (receipt/provision/env deltas rank highest:
// they are unfakeable installation facts, unlike strings which both envs share)
#include "ax_diff.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
static int keyof(const ax_finding_t *f, char *out, size_t cap) {
  return snprintf(out, cap, "%s|%s", f->stage, f->title);
}
static int find_key(const ax_db_t *db, const char *key) {
  char k[800];
  for (int i = 0; i < db->count; i++) {
    keyof(&db->items[i], k, sizeof(k));
    if (!strcmp(k, key)) return i;
  }
  return -1;
}
// explanatory weight: installation facts > behavior > strings
static int weight(const ax_finding_t *f) {
  if (!strcmp(f->stage, "codesign") || !strcmp(f->stage, "receipt")) return 100;
  if (!strcmp(f->stage, "environ")) return 80;
  if (!strcmp(f->stage, "dylibs")) return 70;
  if (!strcmp(f->stage, "correlate")) return 60;
  if (!strcmp(f->stage, "imports")) return 40;
  if (!strcmp(f->stage, "symbols")) return 30;
  if (!strcmp(f->stage, "strings")) return 10;
  return 20;
}
int ax_diff(const ax_db_t *a, const ax_db_t *b, ax_db_t *out) {
  int n = 0;
  char k[800];
  // B-only and changed rows
  for (int i = 0; i < b->count; i++) {
    keyof(&b->items[i], k, sizeof(k));
    int j = find_key(a, k);
    if (j < 0) {
      char t[220], e[768];
      snprintf(t, sizeof(t), "DELTA B-only: %s", b->items[i].title);
      snprintf(e, sizeof(e), "present in FAILING env, absent in working env. A-evidence: [%s] (w=%d)",
        b->items[i].evidence, weight(&b->items[i]));
      ax_db_add(out, b->items[i].cat, b->items[i].conf, "delta", t, e, b->items[i].vaddr,
        weight(&b->items[i]));
      n++;
    } else if (strcmp(a->items[j].evidence, b->items[i].evidence)) {
      char t[220], e[768];
      snprintf(t, sizeof(t), "DELTA changed: %s", b->items[i].title);
      snprintf(e, sizeof(e), "A: [%s] || B: [%s] (w=%d)", a->items[j].evidence,
        b->items[i].evidence, weight(&b->items[i]));
      ax_db_add(out, b->items[i].cat, b->items[i].conf, "delta", t, e, b->items[i].vaddr,
        weight(&b->items[i]));
      n++;
    }
  }
  // A-only rows (protections present on device but missing on mac = capability gap, lower weight)
  for (int i = 0; i < a->count; i++) {
    keyof(&a->items[i], k, sizeof(k));
    if (find_key(b, k) < 0) {
      char t[220], e[768];
      snprintf(t, sizeof(t), "DELTA A-only: %s", a->items[i].title);
      snprintf(e, sizeof(e), "present in WORKING env only (capability gap, not conviction evidence)");
      ax_db_add(out, a->items[i].cat, AX_LOW, "delta", t, e, a->items[i].vaddr, 5);
      n++;
    }
  }
  return n;
}
static int cmpd(const void *pa, const void *pb) {
  const ax_finding_t *x = pa, *y = pb;
  if (x->signals != y->signals) return y->signals - x->signals;
  return y->conf - x->conf;
}
void ax_diff_rank(ax_db_t *d) {
  qsort(d->items, d->count, sizeof(ax_finding_t), cmpd);
}
