// main.c — sentinelforge CLI (lab research ONLY)
//
// Usage:
//   sentinelforge analyze --binary PATH --appdir DIR --label NAME --out DIR
//     full iterative pipeline -> DIR/report.json + DIR/report.md
//   sentinelforge diff --a DIR_A --b DIR_B --out DIR
//     needs prior: sentinelforge analyze ... --dump DIR_A/db.json (use --dump to persist db)
//     simpler: diff --abin A --aapp APPA --alabel A --bbin B --bapp APPB --blabel B --out DIR
//   sentinelforge version
#include "ax_common.h"
#include "ax_context.h"
#include "ax_iterate.h"
#include "ax_report.h"
#include "ax_diff.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

static void usage(void) {
  printf("sentinelforge — forensic binary-analysis platform (authorized lab use)\n");
  printf("  analyze --binary B --appdir A --label L --out D [--passes N] [--verbose]\n");
  printf("  diff --abin A --aapp AA --alabel LA --bbin B --bapp AB --blabel LB --out D\n");
  printf("  version\n");
}
static const char *flag(int argc, char **argv, const char *k) {
  for (int i = 0; i + 1 < argc; i++)
    if (!strcmp(argv[i], k)) return argv[i + 1];
  return NULL;
}
static int hasflag(int argc, char **argv, const char *k) {
  for (int i = 0; i < argc; i++)
    if (!strcmp(argv[i], k)) return 1;
  return 0;
}
static void mkout(const char *d) {
  char cmd[1152];
  snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", d);
  system(cmd);
}
static int cmd_analyze(int argc, char **argv) {
  const char *bin = flag(argc, argv, "--binary");
  const char *app = flag(argc, argv, "--appdir");
  const char *label = flag(argc, argv, "--label");
  const char *out = flag(argc, argv, "--out");
  const char *ps = flag(argc, argv, "--passes");
  if (!bin || !out) { usage(); return 2; }
  if (hasflag(argc, argv, "--verbose")) ax_set_verbose(2);
  mkout(out);
  struct ax_ctx_s ctx;
  if (ax_ctx_build(&ctx, bin, app ? app : "", label ? label : bin) != 0) return 1;
  ax_iter_cfg_t cfg;
  cfg.max_passes = ps ? atoi(ps) : 4;
  cfg.material_min = 1;
  cfg.verbose = 0;
  ax_iter_result_t res;
  ax_iterate(&ctx, &cfg, &res);
  char jp[1200], mp[1200];
  snprintf(jp, sizeof(jp), "%s/report.json", out);
  snprintf(mp, sizeof(mp), "%s/report.md", out);
  ax_report_write(&ctx.db, ctx.label, jp, mp);
  printf("passes=%d promotions=%d findings=%d\n open-questions:\n%s\nWrote %s %s\n",
    res.passes_done, res.promotions, res.total_added, res.open_questions, jp, mp);
  ax_ctx_free(&ctx);
  return 0;
}
static int cmd_diff(int argc, char **argv) {
  const char *abin = flag(argc, argv, "--abin");
  const char *aapp = flag(argc, argv, "--aapp");
  const char *alab = flag(argc, argv, "--alabel");
  const char *bbin = flag(argc, argv, "--bbin");
  const char *bapp = flag(argc, argv, "--bapp");
  const char *blab = flag(argc, argv, "--blabel");
  const char *out = flag(argc, argv, "--out");
  if (!abin || !bbin || !out) { usage(); return 2; }
  if (hasflag(argc, argv, "--verbose")) ax_set_verbose(2);
  mkout(out);
  struct ax_ctx_s ca, cb;
  if (ax_ctx_build(&ca, abin, aapp ? aapp : "", alab ? alab : abin) != 0) return 1;
  ax_iter_cfg_t cfg = {4, 1, 0};
  ax_iter_result_t r1, r2;
  ax_iterate(&ca, &cfg, &r1);
  if (ax_ctx_build(&cb, bbin, bapp ? bapp : "", blab ? blab : bbin) != 0) { ax_ctx_free(&ca); return 1; }
  ax_iterate(&cb, &cfg, &r2);
  ax_db_t deltas;
  memset(&deltas, 0, sizeof(deltas));
  int n = ax_diff(&ca.db, &cb.db, &deltas);
  ax_diff_rank(&deltas);
  char aj[1200], am[1200], bj[1200], bm[1200], dm[1200];
  snprintf(aj, sizeof(aj), "%s/a.json", out); snprintf(am, sizeof(am), "%s/a.md", out);
  snprintf(bj, sizeof(bj), "%s/b.json", out); snprintf(bm, sizeof(bm), "%s/b.md", out);
  snprintf(dm, sizeof(dm), "%s/DELTA.md", out);
  ax_report_write(&ca.db, ca.label, aj, am);
  ax_report_write(&cb.db, cb.label, bj, bm);
  ax_report_delta(&deltas, ca.label, cb.label, dm);
  printf("A=%d B=%d deltas=%d\nWrote %s %s\n", ca.db.count, cb.db.count, n, dm, out);
  ax_ctx_free(&ca);
  ax_ctx_free(&cb);
  return 0;
}
int main(int argc, char **argv) {
  if (argc < 2) { usage(); return 2; }
  if (!strcmp(argv[1], "version")) { printf("sentinelforge 1.0.0-leviathan\n"); return 0; }
  if (!strcmp(argv[1], "analyze")) return cmd_analyze(argc - 1, argv + 1);
  if (!strcmp(argv[1], "diff")) return cmd_diff(argc - 1, argv + 1);
  usage();
  return 2;
}
