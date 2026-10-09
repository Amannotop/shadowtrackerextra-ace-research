#include <stdio.h>
// ax_symbols.c — symtab parse (bounds-checked), gracefully handles stripped binaries
#include "ax_symbols.h"
#include <stdlib.h>
#include <string.h>
#define LC_SYMTAB 0x2
#define N_STAB 0xe0
#define N_TYPE 0x0e
#define N_SECT 0x0e
int ax_symtab_load(const ax_image_t *img, ax_symtab_t *out, ax_db_t *db) {
  memset(out, 0, sizeof(*out));
  const uint8_t *m = img->img;
  if (img->img_len < 32) return -1;
  uint32_t ncmd;
  memcpy(&ncmd, m + 16, 4);
  const uint8_t *lc = m + 32;
  uint32_t symoff = 0, nsyms = 0, stroff = 0, strsz = 0;
  for (uint32_t i = 0; i < ncmd && i < 256; i++) {
    if (lc + 8 > m + img->img_len) break;
    uint32_t cmd, sz;
    memcpy(&cmd, lc, 4); memcpy(&sz, lc + 4, 4);
    if (sz < 8 || lc + sz > m + img->img_len) break;
    if (cmd == LC_SYMTAB && sz >= 24) {
      memcpy(&symoff, lc + 8, 4); memcpy(&nsyms, lc + 12, 4);
      memcpy(&stroff, lc + 16, 4); memcpy(&strsz, lc + 20, 4);
    }
    lc += sz;
  }
  if (!nsyms || !strsz) {
    ax_db_add(db, AXCAT_MISC, AX_MED, "symbols", "symtab-absent",
      "stripped binary: no symtab; string+xref evidence only (confidence capped at HIGH)", 0, 1);
    return 1; // not fatal
  }
  if (nsyms > 2000000) return -1; // malformed guard
  // NOTE: symoff/stroff are FILE offsets relative to slice? For thin slices == file. For fat
  // slices they are slice-relative per Mach-O (linkedit in slice). We resolve against img base.
  if ((uint64_t)symoff + (uint64_t)nsyms * 16 > img->img_len) return -1;
  if ((uint64_t)stroff + strsz > img->img_len) return -1;
  out->v = calloc(nsyms > 200000 ? 200000 : nsyms, sizeof(ax_sym_t));
  const uint8_t *ent = img->img + symoff;
  const uint8_t *str = img->img + stroff;
  for (uint32_t i = 0; i < nsyms && (int)i < 200000; i++, ent += 16) {
    uint32_t si;
    memcpy(&si, ent, 4);
    uint8_t type = ent[4], sect = ent[5];
    uint64_t val;
    memcpy(&val, ent + 8, 8);
    if (type & N_STAB) continue;
    const char *nm = (si < strsz) ? (const char *)(str + si) : "?";
    // validate cstring bounds
    size_t maxl = strsz - si;
    size_t L = strnlen(nm, maxl > 160 ? 160 : maxl);
    if (L == 0 || L >= 160) continue;
    ax_sym_t *s = &out->v[out->n++];
    memcpy(s->name, nm, L); s->name[L] = 0;
    s->type = type; s->sect = sect; s->val = val;
    if ((type & N_TYPE) == 0 && !(type & 0x01)) { s->is_import = 1; out->nund++; }
    else if ((type & N_TYPE) == N_SECT) { out->ndef++; }
    else if ((type & N_TYPE) == 0) { s->is_import = 1; out->nund++; }
  }
  char ev[160];
  snprintf(ev, sizeof(ev), "symtab entries=%u kept=%d defined~%d undefined~%d", nsyms, out->n, out->ndef, out->nund);
  ax_db_add(db, AXCAT_MISC, AX_HIGH, "symbols", "symtab-summary", ev, 0, 2);
  return 0;
}
void ax_symtab_free(ax_symtab_t *t) { free(t->v); memset(t, 0, sizeof(*t)); }
int ax_symtab_exports(const ax_symtab_t *t, const char *substr, ax_db_t *db, ax_cat_t cat) {
  int n = 0;
  for (int i = 0; i < t->n; i++) {
    if (!t->v[i].is_import && strstr(t->v[i].name, substr)) {
      char ti[200], ev[320];
      snprintf(ti, sizeof(ti), "export %s", t->v[i].name);
      snprintf(ev, sizeof(ev), "defined @0x%llx (control-seam candidate — map callers, hook-order target)",
        (unsigned long long)t->v[i].val);
      ax_db_add(db, cat, AX_HIGH, "symbols", ti, ev, t->v[i].val, 2);
      n++;
    }
  }
  return n;
}
