// ax_imports.h — security-API inventory + dylib/framework analysis (SentinelForge)
#ifndef AX_IMPORTS_H
#define AX_IMPORTS_H
#include "ax_macho.h"
#include "ax_symbols.h"
// Inventory vs known security-API table; evidence cites role + import presence.
// Also flags: unexpected/unsigned third-party dylibs, missing-framework anomalies.
int ax_imports_inventory(const ax_image_t *img, const ax_symtab_t *sym, ax_db_t *db);
int ax_dylibs_analyze(const ax_image_t *img, ax_db_t *db);
#endif
