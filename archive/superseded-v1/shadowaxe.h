// shadowaxe.h — forensic binary-analysis framework (lab research ONLY)
// Multi-stage pipeline: Mach-O -> symbols -> ObjC -> strings+score -> imports ->
// xrefs -> callgraph -> checks -> correlation -> prioritized JSON report.
#ifndef SHADOWAXE_H
#define SHADOWAXE_H
#include <stdint.h>
#include <stddef.h>

// Confidence levels
typedef enum { AX_LOW = 1, AX_MED = 2, AX_HIGH = 3, AX_CONFIRMED = 4 } ax_conf_t;

// Finding categories
typedef enum {
  AXCAT_DEBUG = 0, AXCAT_JB, AXCAT_DYLIB, AXCAT_SIG, AXCAT_NET,
  AXCAT_KC, AXCAT_MACH, AXCAT_REPORT, AXCAT_CRYPTO, AXCAT_THREAD, AXCAT_MISC
} ax_cat_t;

typedef struct {
  char id[32];            // AX-0001…
  ax_cat_t cat;
  ax_conf_t conf;
  char title[128];
  char evidence[512];     // why: addrs, names, bytes
  char refs[512];         // callers/callees/xrefs (filled by correlation stage)
  uint64_t vaddr;         // primary location (0 if n/a)
} ax_finding_t;

// Pipeline API (dylib exports)
int ax_analyze(const char *path, const char *out_json); // full pipeline -> JSON report
int ax_stage(const char *path, int stage, const char *out_json); // single stage (0..8)
const char *ax_version(void);

#endif
