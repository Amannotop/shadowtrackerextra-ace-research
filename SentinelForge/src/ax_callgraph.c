// ax_callgraph.c — caller maps + bounded reachability (cycle-safe, depth-capped)
#include "ax_callgraph.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int ax_cg_build(const ax_xref_t *x, const ax_symtab_t *s, ax_cg_t *out, ax_db_t *db) {
  memset(out, 0, sizeof(*out));
  (void)s;
  // unique fn nodes from edge sources
  size_t cap = 0;
  for (int i = 0; i < x->n; i++) {
    if (strcmp(x->v[i].kind, "bl")) continue;
    uint64_t f = x->v[i].from_va;
    int k;
    for (k = 0; k < out->n; k++) if (out->v[k].fn == f) break;
    if (k == out->n) {
      if (out->n >= (int)cap) { cap = cap ? cap * 2 : 1024; out->v = realloc(out->v, cap * sizeof(ax_node_t)); }
      out->v[out->n].fn = f; out->v[out->n].ncallers = 0; out->v[out->n].ncallees = 0;
      out->n++;
    }
  }
  // callees per fn; callers per fn via reverse scan
  for (int i = 0; i < out->n; i++) {
    int ce = 0, cr = 0;
    for (int j = 0; j < x->n; j++) {
      if (strcmp(x->v[j].kind, "bl")) continue;
      if (x->v[j].from_va == out->v[i].fn) ce++;
    }
    // callers: distinct from_va values targeting any edge OUT of this fn? No — callers
    // need edges INTO fn. Our edges point fn->target; callers of F = edges with to_va in F's range.
    // Without fn bounds we approximate: callers = bl-edges whose target == fn start (direct recursion/entry refs).
    for (int j = 0; j < x->n; j++) {
      if (!strcmp(x->v[j].kind, "bl") && x->v[j].to_va == out->v[i].fn) cr++;
    }
    out->v[i].ncallees = ce; out->v[i].ncallers = cr;
  }
  char ev[160];
  snprintf(ev, sizeof(ev), "callgraph nodes=%d (fn-start heuristic; caller counts are direct-target only)", out->n);
  ax_db_add(db, AXCAT_MISC, AX_MED, "callgraph", "callgraph-summary", ev, 0, 1);
  return 0;
}
void ax_cg_free(ax_cg_t *c) { free(c->v); memset(c, 0, sizeof(*c)); }
int ax_cg_callers(const ax_cg_t *c, const ax_xref_t *x, uint64_t target_va, char *out, size_t cap) {
  (void)c;
  // direct bl-callers within ±0x400 (stubs/thunks), plus list
  size_t o = 0;
  int n = 0;
  for (int i = 0; i < x->n; i++) {
    if (strcmp(x->v[i].kind, "bl")) continue;
    uint64_t d = x->v[i].to_va > target_va ? x->v[i].to_va - target_va : target_va - x->v[i].to_va;
    if (d <= 0x400) {
      n++;
      if (o + 32 < cap) o += snprintf(out + o, cap - o, "0x%llx ", (unsigned long long)x->v[i].from_va);
    }
  }
  return n;
}
// bounded DFS over fn->target edges where target resolves to a known fn start; fallback: direct-edge check
int ax_cg_reaches(const ax_cg_t *c, const ax_xref_t *x, uint64_t from_fn, uint64_t target_va, int depth) {
  if (depth <= 0) return 0;
  for (int i = 0; i < x->n; i++) {
    if (strcmp(x->v[i].kind, "bl") || x->v[i].from_va != from_fn) continue;
    uint64_t t = x->v[i].to_va;
    uint64_t d = t > target_va ? t - target_va : target_va - t;
    if (d <= 0x400) return 1;
    // recurse if t is itself a known fn node
    for (int k = 0; k < c->n; k++) {
      if (c->v[k].fn == t && ax_cg_reaches(c, x, t, target_va, depth - 1)) return 1;
    }
  }
  return 0;
}
