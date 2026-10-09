#include <stdio.h>
// ax_context.c — owns collectors in dependency order (macho -> symbols/strings -> imports -> xref -> cg -> bundle modules)
#include "ax_context.h"
#include "ax_imports.h"
#include "ax_codesign.h"
#include "ax_receipt.h"
#include "ax_environ.h"
#include <string.h>
int ax_ctx_build(struct ax_ctx_s *ctx, const char *binary, const char *appdir, const char *label) {
  memset(ctx, 0, sizeof(*ctx));
  snprintf(ctx->binary, sizeof(ctx->binary), "%.1023s", binary);
  snprintf(ctx->appdir, sizeof(ctx->appdir), "%.1023s", appdir ? appdir : "");
  snprintf(ctx->label, sizeof(ctx->label), "%.127s", label ? label : binary);
  if (ax_macho_open(binary, &ctx->img, &ctx->db) != 0) {
    ax_log(0, "macho open failed: %s", binary);
    return -1;
  }
  ax_symtab_load(&ctx->img, &ctx->sym, &ctx->db);
  // export seam inventory (known control-seam prefixes; generic, not game-specific)
  ax_symtab_exports(&ctx->sym, "AnoSDK", &ctx->db, AXCAT_REPORT);
  ax_symtab_exports(&ctx->sym, "CheckSymbolSource", &ctx->db, AXCAT_DYLIB);
  ax_strings_scan(&ctx->img, &ctx->str, &ctx->db);
  ax_imports_inventory(&ctx->img, &ctx->sym, &ctx->db);
  ax_dylibs_analyze(&ctx->img, &ctx->db);
  ax_xref_scan(&ctx->img, &ctx->xr, &ctx->db);
  ax_cg_build(&ctx->xr, &ctx->sym, &ctx->cg, &ctx->db);
  if (ctx->appdir[0]) {
    // main binary path for cryptid note: appdir/<executable>? use ctx->binary (may be framework dylib)
    ax_codesign_analyze(ctx->appdir, ctx->binary, &ctx->db);
    ax_receipt_analyze(&ctx->img, ctx->appdir, &ctx->db);
    ax_environ_analyze(&ctx->img, ctx->appdir, &ctx->db);
  } else {
    ax_environ_analyze(&ctx->img, ".", &ctx->db);
  }
  return 0;
}
void ax_ctx_free(struct ax_ctx_s *ctx) {
  ax_macho_close(&ctx->img);
  ax_symtab_free(&ctx->sym);
  ax_strings_free(&ctx->str);
  ax_xref_free(&ctx->xr);
  ax_cg_free(&ctx->cg);
}
