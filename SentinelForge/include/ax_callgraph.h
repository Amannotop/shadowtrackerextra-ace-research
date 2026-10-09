// ax_callgraph.h — caller/callee maps + chain tracing (SentinelForge)
#ifndef AX_CALLGRAPH_H
#define AX_CALLGRAPH_H
#include "ax_xref.h"
#include "ax_symbols.h"
typedef struct { uint64_t fn; int ncallers; int ncallees; } ax_node_t;
typedef struct { ax_node_t *v; int n; } ax_cg_t;
int ax_cg_build(const ax_xref_t *x, const ax_symtab_t *s, ax_cg_t *out, ax_db_t *db);
void ax_cg_free(ax_cg_t *c);
// chain: callers-of(sym) with depths; writes refs text into finding refs
int ax_cg_callers(const ax_cg_t *c, const ax_xref_t *x, uint64_t target_va, char *out, size_t cap);
// does any path fn -> ... -> target exist within depth? (bounded DFS)
int ax_cg_reaches(const ax_cg_t *c, const ax_xref_t *x, uint64_t from_fn, uint64_t target_va, int depth);
#endif
