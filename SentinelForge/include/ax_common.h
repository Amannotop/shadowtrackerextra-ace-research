// ax_common.h — shared types, finding store, logging (SentinelForge)
#ifndef AX_COMMON_H
#define AX_COMMON_H
#include <stdint.h>
#include <stddef.h>

typedef enum { AX_LOW=1, AX_MED=2, AX_HIGH=3, AX_CONFIRMED=4 } ax_conf_t;
typedef enum { AXCAT_DEBUG=0, AXCAT_JB, AXCAT_DYLIB, AXCAT_SIG, AXCAT_NET,
  AXCAT_KC, AXCAT_MACH, AXCAT_REPORT, AXCAT_CRYPTO, AXCAT_THREAD,
  AXCAT_ENV, AXCAT_CODEIGN, AXCAT_RECEIPT, AXCAT_MISC } ax_cat_t;

typedef struct {
  char id[16]; char title[160]; char evidence[768]; char refs[768];
  ax_cat_t cat; ax_conf_t conf; uint64_t vaddr; int signals; char stage[24];
} ax_finding_t;

#define AX_MAX_FINDINGS 4096
typedef struct {
  ax_finding_t items[AX_MAX_FINDINGS];
  int count; int seq;
} ax_db_t;

void ax_db_add(ax_db_t *db, ax_cat_t cat, ax_conf_t conf, const char *stage,
  const char *title, const char *evidence, uint64_t vaddr, int signals);
const char *ax_cat_name(ax_cat_t c);
const char *ax_conf_name(ax_conf_t c);

// diagnostics: levels 0 quiet, 1 info, 2 verbose
void ax_log(int level, const char *fmt, ...);
void ax_set_verbose(int v);

#endif
