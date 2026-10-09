// ax_report.h — executive + technical JSON/markdown report (SentinelForge)
#ifndef AX_REPORT_H
#define AX_REPORT_H
#include "ax_common.h"
// Writes JSON report (machine) + markdown (human). Returns 0 ok.
int ax_report_write(const ax_db_t *db, const char *target_label, const char *json_path, const char *md_path);
// delta report (A vs B): ranked hypotheses + evidence table + open questions
int ax_report_delta(const ax_db_t *deltas, const char *label_a, const char *label_b, const char *md_path);
#endif
