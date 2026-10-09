// ax_iterate.h — iterative pipeline: analyze->correlate->investigate->validate->refine->repeat
// Stops when a pass adds no material findings (threshold configurable) or max passes hit.
// Each pass records: findings added, chains promoted, open questions (evidence gaps).
#ifndef AX_ITERATE_H
#define AX_ITERATE_H
#include "ax_common.h"
typedef struct {
  int max_passes;      // default 4
  int material_min;    // new HIGH+/CONFIRMED needed to continue (default 1)
  int verbose;
} ax_iter_cfg_t;
typedef struct {
  int passes_done; int total_added; int promotions;
  char open_questions[2048];
} ax_iter_result_t;
struct ax_ctx_s;
int ax_iterate(struct ax_ctx_s *ctx, const ax_iter_cfg_t *cfg, ax_iter_result_t *res);
#endif
