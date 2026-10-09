// ax_xref.h — literal-use sites + branch/call edges (SentinelForge)
#ifndef AX_XREF_H
#define AX_XREF_H
#include "ax_macho.h"
typedef struct { uint64_t from_va; uint64_t to_va; char kind[12]; } ax_edge_t; // kind: bl/call/adrp-lit
typedef struct { ax_edge_t *v; int n; long bl_total; long lit_total; } ax_xref_t;
int ax_xref_scan(const ax_image_t *img, ax_xref_t *out, ax_db_t *db);
void ax_xref_free(ax_xref_t *x);
// edges whose target ~= symbol value (import/export call sites)
int ax_xref_calls_to(const ax_xref_t *x, uint64_t target_va, uint64_t window);
#endif
