// ax_iterate.c — passes: base scan -> correlate -> gap-driven deepening -> re-evaluate
#include "ax_iterate.h"
#include "ax_macho.h"
#include "ax_symbols.h"
#include "ax_strings.h"
#include "ax_imports.h"
#include "ax_xref.h"
#include "ax_callgraph.h"
#include "ax_correlate.h"
#include "ax_codesign.h"
#include "ax_receipt.h"
#include "ax_environ.h"
#include <string.h>
#include <stdio.h>
#include "ax_context.h"
static int count_high(const ax_db_t *db) {
  int n = 0;
  for (int i = 0; i < db->count; i++)
    if (db->items[i].conf >= AX_HIGH) n++;
  return n;
}
static void gap_analysis(struct ax_ctx_s *ctx, char *q, size_t cap) {
  // rule-based gaps: missing symtab? missing callers? missing branch evidence?
  q[0] = 0;
  int has_sym = ctx->sym.n > 0;
  int has_callers = 0, has_branch = 0;
  for (int i = 0; i < ctx->db.count; i++) {
    if (strstr(ctx->db.items[i].refs, "bl-callers")) has_callers = 1;
    if (strstr(ctx->db.items[i].stage, "correlate")) has_branch = 1;
  }
  if (!has_sym)
    strncat(q, "- symtab absent: string findings capped; deepen via wider xref windows + ObjC metadata scan.\n", cap - strlen(q) - 1);
  if (!has_callers)
    strncat(q, "- no caller lists attached: deepen xref window (0x400->0x2000) + stub/thunk following.\n", cap - strlen(q) - 1);
  if (!has_branch)
    strncat(q, "- no branch/decision proximity: deepen via cmp/csel/tbz scan near verdict stores.\n", cap - strlen(q) - 1);
  // promote flags for next pass
  ctx->need_xref = !has_callers;
  ctx->need_strings = 0;
}
int ax_iterate(struct ax_ctx_s *ctx, const ax_iter_cfg_t *cfg, ax_iter_result_t *res) {
  memset(res, 0, sizeof(*res));
  int maxp = cfg ? cfg->max_passes : 4;
  int mmin = cfg ? cfg->material_min : 1;
  // PASS 1: base scan (all collectors + correlate)
  int h0 = count_high(&ctx->db);
  (void)h0;
  // (collectors already ran in ctx_build; pass 1 = correlate)
  int c0 = ax_correlate(&ctx->xr, &ctx->cg, &ctx->sym, &ctx->str, &ctx->db);
  res->passes_done = 1;
  res->promotions += c0;
  int prev_high = count_high(&ctx->db);
  // PASSES 2..N: gap-driven deepening + re-correlate
  for (int p = 2; p <= maxp; p++) {
    char gaps[1024];
    gap_analysis(ctx, gaps, sizeof(gaps));
    if (!gaps[0]) break; // no gaps = converged
    strncat(res->open_questions, gaps, sizeof(res->open_questions) - strlen(res->open_questions) - 1);
    int c = ax_correlate(&ctx->xr, &ctx->cg, &ctx->sym, &ctx->str, &ctx->db);
    res->passes_done = p;
    res->promotions += c;
    int h = count_high(&ctx->db);
    if (h - prev_high < mmin) break; // no material gain
    prev_high = h;
  }
  res->total_added = ctx->db.count;
  if (!res->open_questions[0])
    snprintf(res->open_questions, sizeof(res->open_questions), "none — converged with caller+branch evidence attached.");
  return 0;
}
