// ax_correlate.h — chain builder: indicator->ref->fn->caller/callee->check->decision (SentinelForge)
// Promotions require >=2 independent signals; every promotion cites its evidence.
#ifndef AX_CORRELATE_H
#define AX_CORRELATE_H
#include "ax_common.h"
#include "ax_xref.h"
#include "ax_callgraph.h"
#include "ax_symbols.h"
#include "ax_strings.h"
int ax_correlate(const ax_xref_t *x, const ax_cg_t *cg, const ax_symtab_t *sym,
  const ax_strings_t *str, ax_db_t *db);
#endif
