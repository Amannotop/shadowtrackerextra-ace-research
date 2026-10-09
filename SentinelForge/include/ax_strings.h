// ax_strings.h — census + weighted indicator scoring (SentinelForge)
// Scoring is multi-evidence: a string alone caps at MED; promotion to HIGH/CONFIRMED
// happens ONLY in correlate/ (xref + caller + branch + report-chain agreement).
#ifndef AX_STRINGS_H
#define AX_STRINGS_H
#include "ax_macho.h"
typedef struct { char text[200]; uint64_t foff; uint64_t vaddr; int score; ax_cat_t cat; char why[96]; } ax_hit_t;
typedef struct { ax_hit_t *v; int n; long total; } ax_strings_t;
int ax_strings_scan(const ax_image_t *img, ax_strings_t *out, ax_db_t *db);
void ax_strings_free(ax_strings_t *s);
#endif
