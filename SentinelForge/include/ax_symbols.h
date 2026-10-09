// ax_symbols.h — symtab/dysymtab + export/import lists (SentinelForge)
#ifndef AX_SYMBOLS_H
#define AX_SYMBOLS_H
#include "ax_macho.h"
typedef struct { char name[160]; uint8_t type; uint8_t sect; uint64_t val; int is_import; } ax_sym_t;
typedef struct { ax_sym_t *v; int n; int ndef, nund; } ax_symtab_t;
int ax_symtab_load(const ax_image_t *img, ax_symtab_t *out, ax_db_t *db);
void ax_symtab_free(ax_symtab_t *t);
// export inventory filtered by predicate substring (e.g. "AnoSDK"); imports similarly
int ax_symtab_exports(const ax_symtab_t *t, const char *substr, ax_db_t *db, ax_cat_t cat);
#endif
