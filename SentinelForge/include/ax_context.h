// ax_context.h — analysis context: binary+bundle owned data + build/free (SentinelForge)
#ifndef AX_CONTEXT_H
#define AX_CONTEXT_H
#include "ax_common.h"
#include "ax_macho.h"
#include "ax_symbols.h"
#include "ax_strings.h"
#include "ax_xref.h"
#include "ax_callgraph.h"
struct ax_ctx_s {
  char binary[1024]; char appdir[1024]; char label[128];
  ax_db_t db;
  ax_image_t img; ax_symtab_t sym; ax_strings_t str; ax_xref_t xr; ax_cg_t cg;
  int need_strings, need_xref;
};
// binary + optional appdir ("" = binary-only). Runs all collectors (not correlate).
int ax_ctx_build(struct ax_ctx_s *ctx, const char *binary, const char *appdir, const char *label);
void ax_ctx_free(struct ax_ctx_s *ctx);
#endif
