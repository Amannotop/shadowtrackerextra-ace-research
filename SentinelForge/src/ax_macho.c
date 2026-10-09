// ax_macho.c — bounds-checked Mach-O + fat parser, LC segment/dylib walk
#include "ax_macho.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define MH_MAGIC_64 0xfeedfacf
#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca
#define LC_SEGMENT_64 0x19
#define LC_SYMTAB 0x2
#define CPU_TYPE_ARM64 16777228

static uint32_t r32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint32_t r32be(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return __builtin_bswap32(v); }
static uint64_t r64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
// checked slice reader: returns 0 ok
static int need(const ax_image_t *im, const uint8_t *p, size_t n) {
  return (p >= im->img && p + n <= im->img + im->img_len) ? 0 : -1;
}
static int fneed(const ax_image_t *im, const uint8_t *p, size_t n) {
  return (p >= im->file_base && p + n <= im->file_base + im->file_len) ? 0 : -1;
}

int ax_macho_open(const char *path, ax_image_t *img, ax_db_t *db) {
  memset(img, 0, sizeof(*img));
  int fd = open(path, O_RDONLY);
  if (fd < 0) { ax_log(0, "open failed: %s", path); return -1; }
  struct stat st;
  if (fstat(fd, &st) || st.st_size < 32) { close(fd); return -1; }
  uint8_t *p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (p == MAP_FAILED) return -1;
  img->file_base = p; img->file_len = st.st_size;
  img->img = p; img->img_len = st.st_size;
  uint32_t mg = r32(p);
  img->is_fat = (mg == FAT_MAGIC || mg == FAT_CIGAM);
  if (img->is_fat) {
    int be = (mg == FAT_CIGAM);
    uint32_t n = be ? r32be(p + 4) : r32(p + 4);
    int found = 0;
    for (uint32_t i = 0; i < n && i < 16; i++) {
      const uint8_t *a = p + 8 + i * 20;
      if (fneed(img, a, 20)) break;
      uint32_t ct = be ? r32be(a) : r32(a);
      uint32_t off = be ? r32be(a + 8) : r32(a + 8);
      uint32_t sz = be ? r32be(a + 12) : r32(a + 12);
      if (ct == CPU_TYPE_ARM64 && off + sz <= img->file_len && sz > 32) {
        img->img = p + off; img->img_len = sz; found = 1;
        snprintf(img->slice_arch, sizeof(img->slice_arch), "arm64");
        break;
      }
    }
    if (!found) {
      char ev[128];
      snprintf(ev, sizeof(ev), "fat binary, %u slices, no arm64 slice selected (first-slice fallback refused)", n);
      ax_db_add(db, AXCAT_MISC, AX_LOW, "macho", "fat-no-arm64", ev, 0, 1);
      munmap(p, st.st_size);
      return -2;
    }
    char ev[128];
    snprintf(ev, sizeof(ev), "fat arch selected: %s (%u slices total)", img->slice_arch, n);
    ax_db_add(db, AXCAT_MISC, AX_MED, "macho", "fat-slice", ev, 0, 1);
  }
  if (img->img_len < 32 || r32(img->img) != MH_MAGIC_64) {
    ax_log(0, "not arm64 mach-o: %s", path);
    if (!img->is_fat) munmap(p, st.st_size);
    return -2;
  }
  img->is64 = 1;
  // LC walk
  const uint8_t *m = img->img;
  uint32_t ncmd = r32(m + 16);
  const uint8_t *lc = m + 32;
  int capsec = 64, capd = 32;
  img->sections = calloc(capsec, sizeof(ax_section_t));
  img->dylibs = calloc(capd, sizeof(char *));
  for (uint32_t i = 0; i < ncmd && i < 256; i++) {
    if (need(img, lc, 8)) break;
    uint32_t cmd = r32(lc), sz = r32(lc + 4);
    if (sz < 8 || need(img, lc, sz)) break;
    if (cmd == LC_SEGMENT_64 && sz >= 72) {
      if (need(img, lc, 72)) break;
      uint32_t nsec = r32(lc + 64);
      const uint8_t *sec = lc + 72;
      for (uint32_t s = 0; s < nsec && s < 64; s++, sec += 80) {
        if (need(img, sec, 80)) break;
        if (img->nsec >= capsec) break;
        ax_section_t *o = &img->sections[img->nsec++];
        memcpy(o->seg, sec + 16, 16); o->seg[16] = 0;
        memcpy(o->sect, sec, 16); o->sect[16] = 0;
        // NOTE: sectname@0, segname@16, addr@32, size@40, offset@48, ... (struct section_64)
        // careful: layout is sectname[16], segname[16], addr, size, offset, align, reloff, nreloc, flags, res
        memcpy(o->sect, sec, 16); o->sect[16] = 0;
        memcpy(o->seg, sec + 16, 16); o->seg[16] = 0;
        o->vaddr = r64(sec + 32); o->vsize = r64(sec + 40);
        uint32_t off = r32(sec + 48);
        o->foff = off; o->fsize = o->vsize;
        if (!strcmp(o->sect, "__text") && !strcmp(o->seg, "__TEXT")) {
          img->text_vaddr = o->vaddr; img->text_foff = off; img->text_size = o->vsize;
        }
      }
    } else if (cmd == 0xc || cmd == 0x80000022) { // LC_LOAD_DYLIB / WEAK
      if (sz >= 28) {
        uint32_t noff = r32(lc + 24);
        if (noff < sz) {
          const char *nm = (const char *)(lc + noff);
          size_t maxl = sz - noff;
          size_t L = strnlen(nm, maxl > 256 ? 256 : maxl);
          if (L > 0 && L < 256 && img->ndyl < capd) {
            img->dylibs[img->ndyl] = malloc(L + 1);
            memcpy(img->dylibs[img->ndyl], nm, L);
            img->dylibs[img->ndyl][L] = 0;
            img->ndyl++;
          }
        }
      }
    }
    lc += sz;
  }
  char ev[192];
  snprintf(ev, sizeof(ev), "sections=%d dylibs=%d text_va=0x%llx text_size=0x%llx arch=%s",
    img->nsec, img->ndyl, (unsigned long long)img->text_vaddr,
    (unsigned long long)img->text_size, img->slice_arch[0] ? img->slice_arch : "arm64");
  ax_db_add(db, AXCAT_MISC, AX_HIGH, "macho", "macho-summary", ev, 0, 2);
  return 0;
}
void ax_macho_close(ax_image_t *img) {
  if (!img) return;
  free(img->sections);
  if (img->dylibs) {
    for (int i = 0; i < img->ndyl; i++) free(img->dylibs[i]);
    free(img->dylibs);
  }
  if (img->file_base) munmap((void *)img->file_base, img->file_len);
  memset(img, 0, sizeof(*img));
}
const ax_section_t *ax_macho_section(const ax_image_t *img, const char *seg, const char *sect) {
  for (int i = 0; i < img->nsec; i++)
    if (!strcmp(img->sections[i].seg, seg) && !strcmp(img->sections[i].sect, sect))
      return &img->sections[i];
  return NULL;
}
int64_t ax_macho_va_to_off(const ax_image_t *img, uint64_t va) {
  for (int i = 0; i < img->nsec; i++) {
    const ax_section_t *s = &img->sections[i];
    if (va >= s->vaddr && va < s->vaddr + s->vsize) {
      uint64_t imgva = va - img->text_vaddr; // sections share slide model
      (void)imgva;
      // file offset = section foff + (va - section vaddr), but relative to slice base:
      // section foff is slice-relative already
      return (int64_t)(s->foff + (va - s->vaddr));
    }
  }
  return -1;
}
uint64_t ax_macho_off_to_va(const ax_image_t *img, uint64_t off) {
  for (int i = 0; i < img->nsec; i++) {
    const ax_section_t *s = &img->sections[i];
    if (off >= s->foff && off < s->foff + s->fsize)
      return s->vaddr + (off - s->foff);
  }
  return 0;
}
