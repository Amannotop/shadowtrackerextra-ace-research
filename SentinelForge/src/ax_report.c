// ax_report.c — JSON (machine) + markdown executive/technical (human)
#include "ax_report.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static void jesc(FILE *f, const char *s) {
  for (; *s; s++) {
    if (*s == '"' || *s == '\\') fputc('\\', f);
    if (*s == '\n') { fputs("\\n", f); continue; }
    if ((unsigned char)*s < 32) continue;
    fputc(*s, f);
  }
}
static int cmpf(const void *a, const void *b) {
  const ax_finding_t *x = a, *y = b;
  if (x->conf != y->conf) return y->conf - x->conf;
  return x->cat - y->cat;
}
int ax_report_write(const ax_db_t *db, const char *target_label, const char *json_path, const char *md_path) {
  ax_finding_t *sorted = malloc(sizeof(ax_finding_t) * (db->count ? db->count : 1));
  memcpy(sorted, db->items, sizeof(ax_finding_t) * db->count);
  qsort(sorted, db->count, sizeof(ax_finding_t), cmpf);
  FILE *f = fopen(json_path, "w");
  if (!f) { free(sorted); return -1; }
  fprintf(f, "{\n  \"tool\": \"sentinelforge\",\n  \"target\": \"");
  jesc(f, target_label);
  int nc[5] = {0};
  for (int i = 0; i < db->count; i++) nc[sorted[i].conf]++;
  fprintf(f, "\",\n  \"findings_total\": %d,\n  \"by_confidence\": {\"CONFIRMED\": %d, \"HIGH\": %d, \"MED\": %d, \"LOW\": %d},\n",
    db->count, nc[4], nc[3], nc[2], nc[1]);
  fprintf(f, "  \"findings\": [\n");
  for (int i = 0; i < db->count; i++) {
    ax_finding_t *x = &sorted[i];
    fprintf(f, "    {\"id\": \"%s\", \"cat\": \"%s\", \"conf\": \"%s\", \"stage\": \"%s\", \"signals\": %d, \"vaddr\": \"0x%llx\",\n",
      x->id, ax_cat_name(x->cat), ax_conf_name(x->conf), x->stage, x->signals, (unsigned long long)x->vaddr);
    fprintf(f, "     \"title\": \""); jesc(f, x->title);
    fprintf(f, "\", \"evidence\": \""); jesc(f, x->evidence);
    fprintf(f, "\", \"refs\": \""); jesc(f, x->refs);
    fprintf(f, "\"}%s\n", i + 1 < db->count ? "," : "");
  }
  fprintf(f, "  ]\n}\n");
  fclose(f);
  // markdown: executive summary (top hypotheses) + technical table
  FILE *m = fopen(md_path, "w");
  if (!m) { free(sorted); return -1; }
  fprintf(m, "# SentinelForge Report — %s\n\n", target_label);
  fprintf(m, "Findings: %d (CONFIRMED %d / HIGH %d / MED %d / LOW %d)\n\n", db->count, nc[4], nc[3], nc[2], nc[1]);
  fprintf(m, "## Executive summary (top hypotheses)\n\n");
  int shown = 0;
  for (int i = 0; i < db->count && shown < 12; i++) {
    if (sorted[i].conf < AX_HIGH) break;
    fprintf(m, "%d. **[%s] %s** — %s (signals=%d, %s)\n", shown + 1,
      ax_conf_name(sorted[i].conf), sorted[i].title, sorted[i].evidence,
      sorted[i].signals, sorted[i].stage);
    shown++;
  }
  if (!shown) fprintf(m, "No HIGH+ hypotheses (evidence insufficient — see open questions).\n");
  fprintf(m, "\n## Technical findings (ranked)\n\n");
  fprintf(m, "| ID | Conf | Cat | Stage | Title | Evidence | Refs |\n|---|---|---|---|---|---|---|\n");
  for (int i = 0; i < db->count; i++) {
    // single-line cells: strip newlines/pipes
    char ti[170], ev[300], rf[200];
    int a = 0;
    for (const char *p = sorted[i].title; *p && a < 160; p++) ti[a++] = (*p == '\n' || *p == '|') ? ' ' : *p;
    ti[a] = 0;
    a = 0;
    for (const char *p = sorted[i].evidence; *p && a < 290; p++) ev[a++] = (*p == '\n' || *p == '|') ? ' ' : *p;
    ev[a] = 0;
    a = 0;
    for (const char *p = sorted[i].refs; *p && a < 190; p++) rf[a++] = (*p == '\n' || *p == '|') ? ' ' : *p;
    rf[a] = 0;
    fprintf(m, "| %s | %s | %s | %s | %.150s | %.280s | %.180s |\n", sorted[i].id,
      ax_conf_name(sorted[i].conf), ax_cat_name(sorted[i].cat), sorted[i].stage, ti, ev, rf);
  }
  fclose(m);
  free(sorted);
  return 0;
}
int ax_report_delta(const ax_db_t *deltas, const char *la, const char *lb, const char *md_path) {
  FILE *m = fopen(md_path, "w");
  if (!m) return -1;
  fprintf(m, "# Differential Report — %s (working) vs %s (failing)\n\n", la, lb);
  fprintf(m, "Ranked by explanatory weight: installation facts (codesign/receipt) > environment > modules > behavior > strings.\n\n");
  fprintf(m, "| # | Weight | Conf | Hypothesis (B-side) | Evidence |\n|---|---|---|---|---|\n");
  int k = 0;
  for (int i = 0; i < deltas->count && k < 60; i++) {
    const ax_finding_t *x = &deltas->items[i];
    if (strcmp(x->stage, "delta")) continue;
    char ti[200], ev[400];
    int a = 0;
    for (const char *p = x->title; *p && a < 190; p++) ti[a++] = (*p == '\n' || *p == '|') ? ' ' : *p;
    ti[a] = 0; a = 0;
    for (const char *p = x->evidence; *p && a < 390; p++) ev[a++] = (*p == '\n' || *p == '|') ? ' ' : *p;
    ev[a] = 0;
    fprintf(m, "| %d | %d | %s | %.180s | %.380s |\n", ++k, x->signals, ax_conf_name(x->conf), ti, ev);
  }
  fprintf(m, "\n## Open questions (evidence needed)\n\n");
  fprintf(m, "- Which B-only HIGH finding has a matching live behavior (attach-time transcript)?\n");
  fprintf(m, "- Which changed row's A-value vs B-value was measured at runtime (not assumed)?\n");
  fprintf(m, "- What single removal (per row, one at a time) flips the outcome? (ablation = proof)\n");
  fclose(m);
  return 0;
}
