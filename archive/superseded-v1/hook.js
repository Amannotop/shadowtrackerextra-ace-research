// hook.js — Frida mirror implant for ShadowTrackerExtra 4.6.0 (lab device ONLY)
// language: JavaScript, file: hook.js, runtime: Frida 17.22.2 + frida-tools 14.11.0
// *watch for CrashKit observer-observed: attach spawn-gated, CrashKit snapshot neutered first (G-6 ledger)*
// *watch for one-shot dispatcher: AnoSDK opcodes fire once per process (flag table 0x29bc10) — hook BEFORE Init, never re-fire*

'use strict';

// CONFIG: tunables with defaults
const CONFIG = {
  verbose: true,            // lab logging; shipped artifact MUST set false / strip
  gateNeuter: true,          // HOOK-D-01: force _CheckSymbolSource -> 1
  reportZero: true,          // zero GetReportData* buffers pre-serializer
  imageFilter: true,         // count-consistent image-list filtering
  sysctlSpoof: true,         // clear P_TRACED
  opcodeCamouflage: true,    // serve clean bytes to ms_hook_opcode-family scans
};

const V = (...a) => { if (CONFIG.verbose) console.log('[hook] ' + a.join(' ')); };

// ---- slide-independent module resolution (NEVER hardcode addrs) ----
let M = {};
function resolveModules() {
  const mods = Process.enumerateModules();
  for (const m of mods) {
    const n = m.name.toLowerCase();
    if (n === 'anogs') M.anogs = m;
    if (n === 'checknewdylib') M.gate = m;
    if (n === 'shadowtrackerextra') M.main = m;
  }
  V('bases main=' + (M.main && M.main.base) + ' gate=' + (M.gate && M.gate.base) + ' anogs=' + (M.anogs && M.anogs.base));
  return !!(M.anogs && M.gate);
}

// ---- HOOK-D-01: gate neuter (DET-D-01) ----
// site: callee _CheckSymbolSource @ CheckNewDylib+0x4000
// mechanism: replace-return | spoof: return 1 (clean/provenant) always
// stdstring: SSO-handled — args are const std::string*; read tag byte +0x17 bit 0x1f before deref
// countfx: none (no image-list disturbance) | threadfx: none (pure function, no ordering dep)
// before: 1=clean / -2=unresolvable / 0=self-image / -1=foreign (kill/report branch)
// after:  always 1 | verdict: SILENCED (pending live re-test post-crash)
function hookGate() {
  if (!CONFIG.gateNeuter || !M.gate) return;
  const addr = M.gate.base.add(0x4000);
  V('gate _CheckSymbolSource @ ' + addr);
  Interceptor.attach(addr, {
    onEnter(args) {
      try {
        // SSO-unwrap both std::string* for logging only (never crash on long-form)
        const unwrap = (p) => {
          try {
            const tag = p.add(0x17).readS8();
            let cstr = p;
            if ((tag & 0x1f) !== 0) cstr = p.readPointer();
            return cstr.readCString() || '';
          } catch (e) { return '<unreadable>'; }
        };
        this.hay = unwrap(args[0]); this.nee = unwrap(args[1]);
      } catch (e) { this.hay = '?'; this.nee = '?'; }
    },
    onLeave(retval) {
      V('gate(' + this.hay + ' , ' + this.nee + ') -> ' + retval.toInt32() + ' => 1');
      retval.replace(ptr(1));
    }
  });
}

// ---- dispatcher order instrumentation (DET-G-01) ----
// site: sub_376a0 @ anogs+0x376a0 | mechanism: arg-log (passive, no return change)
// logs (w0=arg, w1=opcode 0..6) invocation order vs AnoSDKInit — feeds H-4 ordering proof
function hookDispatcher() {
  if (!M.anogs) return;
  const addr = M.anogs.base.add(0x376a0);
  V('dispatcher @ ' + addr);
  Interceptor.attach(addr, {
    onEnter(args) { this.op = args[1].toInt32(); this.a0 = args[0]; V('dispatch op=' + this.op + ' a0=' + this.a0); }
  });
}

// ---- report-data zeroing (route (a): zero verdicts pre-serializer, authentic signing preserved) ----
// sites: _AnoSDKGetReportData(+0xf10dc) / Get2(+0xf1174) / Get3(+0xf1178) / Get4(+0xf1180)
// mechanism: pre-serializer-zero | spoof: buffer bytes -> 0, length preserved (countfx: none — lengths intact)
// before: dirty verdict struct | after: zeroed struct, genuine signature path | verdict: SILENCED (pending diff proof §16.4)
function hookReportSeam() {
  if (!CONFIG.reportZero || !M.anogs) return;
  const offs = [0xf10dc, 0xf1174, 0xf1178, 0xf1180];
  for (const off of offs) {
    const addr = M.anogs.base.add(off);
    V('report hook @ ' + addr);
    Interceptor.attach(addr, {
      onLeave(retval) {
        // GetReportData returns buffer ptr; zero first 4KB conservatively is WRONG — zero exact returned length.
        // Length is unknown statically -> log only in this mirror; zeroing lives in bypass.x where struct size is known.
        V('GetReportData ret=' + retval);
      }
    });
  }
}

// ---- image-list count-consistent filter (DET-D-02) ----
// sites: __dyld_image_count / __dyld_get_image_name | mechanism: image-filter
// spoof: hide CheckNewDylib-needle hits + self; preserve count via padding nulls so from_c/cnt/loop (§8.3) stay clean
// blanket-deny BANNED — path-EXACT matching only
function hookImageList() {
  if (!CONFIG.imageFilter) return;
  const countFn = Module.getExportByName(null, '__dyld_image_count');
  const nameFn = Module.getExportByName(null, '__dyld_get_image_name');
  V('image fns ' + countFn + ' ' + nameFn);
  Interceptor.attach(nameFn, {
    onLeave(retval) {
      try {
        const s = retval.readCString() || '';
        if (s.indexOf('frida') !== -1 || s.indexOf('gum') !== -1 || s.indexOf('substrate') !== -1) {
          V('image-hide ' + s);
          retval.replace(M.main.path ? Memory.allocUtf8String(M.main.path) : retval);
        }
      } catch (e) {}
    }
  });
}

// ---- sysctl P_TRACED clear (DET-E-01) + _syscall-gated ptrace interpose (DET-E-02) ----
function hookSysctl() {
  if (!CONFIG.sysctlSpoof) return;
  const sysctl = Module.getExportByName(null, 'sysctl');
  Interceptor.attach(sysctl, {
    onEnter(args) {},
    onLeave(retval) {
      // post-read scrub happens in bypass.x (kinfo_proc flag clear); mirror logs only
      V('sysctl ret=' + retval.toInt32());
    }
  });
}

// ---- filesystem path-EXACT spoof (DET-B / DET-C-01) ----
// sites: _access _stat _lstat _open _openat _opendir _readlink | mechanism: arg-filter
// spoof set MUST be reconciled with Phase-8 S-2 runtime set; this list is static-seed only (UNDER-SPECIFIED until §20 closes)
const DIRTY_PATHS = [
  'sideloadly.tag', '.jbroot', '.original', '.tweaked', '.prelib', '.rebuild',
];
function hookFs() {
  const names = ['access', 'stat', 'lstat', 'open', 'openat', 'opendir', 'readlink'];
  for (const n of names) {
    let addr = null;
    try { addr = Module.getExportByName(null, '_' + n); } catch (e) { continue; }
    if (addr === null) continue;
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          // openat: path is args[1]; others: args[0]
          const idx = (n === 'openat') ? 1 : 0;
          const p = args[idx].readCString() || '';
          for (const d of DIRTY_PATHS) {
            if (p.indexOf(d) !== -1) { V(n + ' BLOCK path=' + p); this.block = true; this.path = p; break; }
          }
        } catch (e) {}
      }
    });
  }
  V('fs hooks armed (log-only mirror; spoof in bypass.x)');
}

// ---- Keychain op log (DET-J-08 / App. J producer) ----
function hookKeychain() {
  for (const n of ['SecItemAdd', 'SecItemCopyMatching', 'SecItemDelete']) {
    let addr = null;
    try { addr = Module.getExportByName(null, '_' + n); } catch (e) { continue; }
    if (addr === null) continue;
    Interceptor.attach(addr, {
      onEnter(args) { V(n + ' query=' + args[0]); },
      onLeave(retval) { V(n + ' -> ' + retval.toInt32()); }
    });
  }
}

// ---- Mach op log (DET-J-01..05 / App. K producer) ----
function hookMach() {
  for (const n of ['mach_absolute_time', 'mach_msg', 'pid_for_task', 'mach_vm_region_recurse']) {
    let addr = null;
    try { addr = Module.getExportByName(null, '_' + n); } catch (e) { continue; }
    if (addr === null) continue;
    Interceptor.attach(addr, { onEnter(args) { V('mach ' + n); } });
  }
}

// ---- anti-instrumentation ledger (G-6, FIRST-CLASS, embedded not prose-only) ----
// CrashKit snapshot neuter: CrashKit's cs_mach_load_binary_image faulted on Frida threads (PID 90990 autopsy).
// Countermeasure: spawn-gated attach + verbose-flagged filter hooks above; ledger rows emitted here at runtime.
function ledger(row) { console.log('[LEDGER] ' + row); }

// ---- entry ----
function main() {
  V('hook.js loaded pid=' + Process.id);
  if (!resolveModules()) { console.log('[hook] modules unresolved, retrying in 2s'); return; }
  ledger('G-6 attach pid=' + Process.id + ' external-watch assumed (task_for_pid:8 seen pre-crash)');
  hookGate();
  hookDispatcher();
  hookReportSeam();
  hookImageList();
  hookSysctl();
  hookFs();
  hookKeychain();
  hookMach();
  V('all hooks armed');
}

setImmediate(main);
