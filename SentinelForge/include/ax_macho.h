// ax_macho.h — Mach-O + fat parsing, LC walk (SentinelForge)
#ifndef AX_MACHO_H
#define AX_MACHO_H
#include "ax_common.h"

typedef struct {
  char seg[17]; char sect[17];
  uint64_t vaddr, vsize, foff, fsize;
} ax_section_t;

typedef struct {
  const uint8_t *file_base; size_t file_len;   // whole file
  const uint8_t *img; size_t img_len;           // selected slice
  int is64; int is_fat; char slice_arch[16];
  uint64_t text_vaddr, text_foff, text_size;
  ax_section_t *sections; int nsec;
  char **dylibs; int ndyl;
  char bundle_id[128]; char bundle_ver[32];    // best-effort (external plist, else empty)
} ax_image_t;

// Returns 0 ok, <0 error. Never crashes on malformed input (bounds-checked).
int ax_macho_open(const char *path, ax_image_t *img, ax_db_t *db);
void ax_macho_close(ax_image_t *img);
// section lookup by seg+sect names
const ax_section_t *ax_macho_section(const ax_image_t *img, const char *seg, const char *sect);
// va -> file offset (-1 fail). foff -> va (0 fail).
int64_t ax_macho_va_to_off(const ax_image_t *img, uint64_t va);
uint64_t ax_macho_off_to_va(const ax_image_t *img, uint64_t off);

#endif
