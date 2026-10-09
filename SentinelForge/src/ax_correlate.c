// ax_correlate.c — evidence-based promotion. Rule: NO promotion on string-only.
// Each chain cites: indicator + reference mechanism + function + caller/callee + decision proximity.
#include "ax_correlate.h"
#include <string.h>
#include <stdio.h>
static int sym_has(const ax_symtab_t *s, const char *sub) {
  for (int i = 0; i < s->n; i++)
    if (strstr(s->v[i].name, sub)) return 1;
  return 0;
}
static int hit_has(const ax_strings_t *s, const char *sub) {
  for (int i = 0; i < s->n; i++)
    if (strstr(s->v[i].text, sub)) return 1;
  return 0;
}
static uint64_t sym_val(const ax_symtab_t *s, const char *sub) {
  for (int i = 0; i < s->n; i++)
    if (!s->v[i].is_import && strstr(s->v[i].name, sub)) return s->v[i].val;
  return 0;
}
int ax_correlate(const ax_xref_t *x, const ax_cg_t *cg, const ax_symtab_t *sym,
  const ax_strings_t *str, ax_db_t *db) {
  int n = 0;
  (void)cg;
  // CHAIN 1: symbol-provenance gate (needs: export + 3 imports + >=1 bl-caller)
  {
    uint64_t gv = sym_val(sym, "CheckSymbolSource");
    int callers = gv ? ax_xref_calls_to(x, gv, 0x400) : 0;
    if (gv && sym_has(sym, "_dlsym") && sym_has(sym, "_dladdr") && sym_has(sym, "_strstr")) {
      char e[700];
      snprintf(e, sizeof(e),
        "export _CheckSymbolSource @0x%llx + imports dlsym/dladdr/strstr + %d bl-caller(s) in window. "
        "Contract 1/-2/0/-1 (verify bytes first). Callers' (symbol,needle) pairs ARE the blocklist — extract every pair. "
        "Neuter: hook gate->1 (one site beats N callers) unless opcode-scan trips it (then caller-arg spoof).",
        (unsigned long long)gv, callers);
      ax_db_add(db, AXCAT_DYLIB, callers > 0 ? AX_CONFIRMED : AX_HIGH, "correlate",
        "chain: symbol-provenance gate", e, gv, 3 + (callers > 0));
      n++;
    }
  }
  // CHAIN 2: report pipeline (needs: keys + seam export + bl-callers)
  {
    int keys = hit_has(str, "tdm_report") + hit_has(str, "cheat_open_id") + hit_has(str, "DoRiskFileTCJTask");
    uint64_t gr = sym_val(sym, "GetReportData");
    int callers = gr ? ax_xref_calls_to(x, gr, 0x400) : 0;
    if (keys >= 2 && gr) {
      char e[700];
      snprintf(e, sizeof(e),
        "%d/3 report keys + GetReportData @0x%llx + %d caller(s). Flow: checks->verdicts->GetReportData->serializer->endpoint->action. "
        "TinyXML envelope witnesses (LinkEndChild) raise to CONFIRMED when present. Route-(a) home: zero verdicts pre-serializer.",
        keys, (unsigned long long)gr, callers);
      ax_db_add(db, AXCAT_REPORT, AX_HIGH, "correlate", "chain: report pipeline", e, gr, 2 + keys);
      n++;
    }
  }
  // CHAIN 3: debugger detection (needs: sysctl/syscall + clock + >=2)
  {
    int s1 = sym_has(sym, "sysctl") || sym_has(sym, "_sysctl");
    int s2 = sym_has(sym, "syscall") || sym_has(sym, "_syscall");
    int s3 = hit_has(str, "mach_absolute_time") || sym_has(sym, "mach_absolute_time");
    int s4 = hit_has(str, "P_TRACED") || hit_has(str, "ptrace");
    if (s1 + s2 + s3 + s4 >= 2) {
      ax_db_add(db, AXCAT_DEBUG, (s1 + s2 + s3 + s4) >= 3 ? AX_HIGH : AX_MED, "correlate",
        "chain: debugger detection",
        "sysctl/syscall + timing clocks + P_TRACED/ptrace co-present. Spoof: P_TRACED clear, _syscall-gated ptrace, clock quantization (margins numeric).", 0,
        s1 + s2 + s3 + s4);
      n++;
    }
  }
  // CHAIN 4: jailbreak probing (needs: oracle format + fs imports)
  {
    int oracle = hit_has(str, "DoRiskFileTCJTask");
    int fs = sym_has(sym, "stat") + sym_has(sym, "access") + sym_has(sym, "open");
    if (oracle && fs >= 2) {
      ax_db_add(db, AXCAT_JB, AX_HIGH, "correlate", "chain: jailbreak probing",
        "DoRiskFileTCJTask oracle + fs interrogation imports. Per-path spoof ONLY (blanket-deny banned); static sets under-specified until runtime recovery closes.", 0, 1 + fs);
      n++;
    }
  }
  // CHAIN 5: receipt/attest (needs: selector + bundle evidence — bundle rows counted via db scan)
  {
    int sel = hit_has(str, "appStoreReceiptURL") + hit_has(str, "attestKey");
    int bund = 0;
    for (int i = 0; i < db->count; i++)
      if (!strcmp(db->items[i].stage, "codesign") || !strcmp(db->items[i].stage, "receipt")) bund++;
    if (sel >= 1 && bund >= 2) {
      ax_db_add(db, AXCAT_RECEIPT, AX_HIGH, "correlate", "chain: receipt/attest/provision",
        "selectors + bundle rows co-present. Absence-handling branch decides sideload fate: find nil/parse-fail outcomes (fail-open vs fail-closed IS the env delta).", 0, sel + 1);
      n++;
    }
  }
  // CHAIN 6: scheduler/watchdog (threads + Ioctl + dispatcher callers)
  {
    int thr = hit_has(str, "ace_worker") + hit_has(str, "ace_schedule") + hit_has(str, "TDM-report");
    uint64_t io = sym_val(sym, "Ioctl");
    int callers = io ? ax_xref_calls_to(x, io, 0x400) : 0;
    if (thr >= 1 && io) {
      char e[512];
      snprintf(e, sizeof(e), "ACE threads + Ioctl @0x%llx (%d callers) + heartbeat cadence. Hook-ordering proofs depend on this map (ctor/priority mistakes = verdict races).",
        (unsigned long long)io, callers);
      ax_db_add(db, AXCAT_THREAD, AX_HIGH, "correlate", "chain: scheduler/watchdog", e, io, thr + 1);
      n++;
    }
  }
  // Attach caller lists to seam export findings (refs field)
  for (int i = 0; i < db->count; i++) {
    ax_finding_t *f = &db->items[i];
    if (!strcmp(f->stage, "symbols") && !strncmp(f->title, "export _AnoSDK", 14)) {
      char callers[512] = "";
      // find export va from title? re-derive: match symtab
      for (int s = 0; s < sym->n; s++) {
        if (!sym->v[s].is_import && strstr(f->title, sym->v[s].name)) {
          char buf[400] = "";
          int nc = ax_cg_callers(cg, x, sym->v[s].val, buf, sizeof(buf));
          snprintf(f->refs, sizeof(f->refs), "bl-callers(%d): %s", nc, buf);
          break;
        }
      }
      (void)callers;
    }
  }
  return n;
}
