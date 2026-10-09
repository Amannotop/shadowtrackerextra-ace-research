#include <stdio.h>
// ax_xref.c — arm64 bl/adrp-add scan with fn-start heuristic (documented, bounded)
#include "ax_xref.h"
#include <stdlib.h>
#include <string.h>
int ax_xref_scan(const ax_image_t *img, ax_xref_t *out, ax_db_t *db) {
  memset(out, 0, sizeof(*out));
  if (!img->text_size || img->text_foff + img->text_size > img->img_len) {
    ax_db_add(db, AXCAT_MISC, AX_LOW, "xref", "xref-skip", "no __text bounds", 0, 0);
    return 1;
  }
  const uint8_t *T = img->img + img->text_foff;
  size_t n = img->text_size & ~(size_t)3;
  uint64_t base = img->text_vaddr;
  size_t cap = 0;
  uint64_t curfn = base;
  long bl = 0, lit = 0;
  for (size_t i = 0; i + 4 <= n; i += 4) {
    uint32_t ins;
    memcpy(&ins, T + i, 4);
    uint64_t va = base + i;
    // fn-start heuristic: stp x29,x30,[sp,#..]! (a9807bfd mask) — over-approximates (FP ok, edges labeled heuristic)
    if ((ins & 0xffc07fff) == 0xa9807bfd || ins == 0xd10043ff) curfn = va;
    if ((ins & 0xfc000000) == 0x94000000) {
      int32_t imm = ins & 0x3ffffff;
      if (imm & 0x2000000) imm |= 0xfc000000;
      uint64_t tgt = va + ((int64_t)imm << 2);
      if (out->n >= (int)cap) { cap = cap ? cap * 2 : 4096; out->v = realloc(out->v, cap * sizeof(ax_edge_t)); }
      out->v[out->n].from_va = curfn; out->v[out->n].to_va = tgt;
      strcpy(out->v[out->n].kind, "bl");
      out->n++; bl++;
    }
    if ((ins & 0x9f000000) == 0x90000000 && i + 8 <= n) {
      uint32_t nx;
      memcpy(&nx, T + i + 4, 4);
      if ((nx & 0xffc00000) == 0x91000000) {
        int pg = (ins >> 5) & 0x7ffff;
        if (pg & 0x40000) pg |= 0xfff80000;
        int imm12 = (nx >> 10) & 0xfff;
        uint64_t page = (va & ~(uint64_t)0xfff) + ((int64_t)pg << 12);
        uint64_t litva = page + imm12;
        if (out->n >= (int)cap) { cap = cap ? cap * 2 : 4096; out->v = realloc(out->v, cap * sizeof(ax_edge_t)); }
        out->v[out->n].from_va = curfn; out->v[out->n].to_va = litva;
        strcpy(out->v[out->n].kind, "adrp-lit");
        out->n++; lit++;
      }
    }
  }
  out->bl_total = bl; out->lit_total = lit;
  char ev[220];
  snprintf(ev, sizeof(ev), "bl-edges=%ld adrp-lit-sites=%ld (fn starts heuristic — edges labeled, FP possible on tail-calls)", bl, lit);
  ax_db_add(db, AXCAT_MISC, AX_HIGH, "xref", "xref-summary", ev, 0, 2);
  return 0;
}
void ax_xref_free(ax_xref_t *x) { free(x->v); memset(x, 0, sizeof(*x)); }
int ax_xref_calls_to(const ax_xref_t *x, uint64_t target_va, uint64_t window) {
  int c = 0;
  for (int i = 0; i < x->n; i++) {
    if (!strcmp(x->v[i].kind, "bl")) {
      uint64_t d = x->v[i].to_va > target_va ? x->v[i].to_va - target_va : target_va - x->v[i].to_va;
      if (d <= window) c++;
    }
  }
  return c;
}
