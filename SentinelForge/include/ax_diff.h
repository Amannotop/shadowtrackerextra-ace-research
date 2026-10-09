// ax_diff.h — cross-environment differential analysis (SentinelForge)
// Compares two report databases (env A = working iOS, env B = failing mac/sideload)
// finding-by-finding on (stage, title) keys; emits DELTA rows ranked by explanatory power.
#ifndef AX_DIFF_H
#define AX_DIFF_H
#include "ax_common.h"
// db_a, db_b: findings from two runs. out: appended DELTA rows. Returns delta count.
int ax_diff(const ax_db_t *db_a, const ax_db_t *db_b, ax_db_t *out);
// rank: inplace sort of DELTA rows by (signals desc, conf desc)
void ax_diff_rank(ax_db_t *deltas);
#endif
