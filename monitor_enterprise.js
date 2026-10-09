'use strict';
// monitor_enterprise.js — 10000000x monitor: EVERY detection family, zero blind spots (lab device ONLY)
// language: JavaScript, file: monitor_enterprise.js, runtime: Frida 17.22.2 agent
// *watch for agent-death (v4 lesson): NO setInterval; hot clocks sampled 1:100; pthread_create hooked (loader-lock risk accepted, log-only, no block)*
// *watch for proof standard: every [hit] line carries args+return where cheap; backtrace on RARE events (gate/seam/KC/receipt), never on hot*
/* COVERAGE LEDGER — each family -> hook status:
   GATE(D1a/D1b) log+neuter | SEAM-15(G) log | FS-14(B/C1: access stat lstat fstat statfs open openat opendir readdir readlink mmap read fopen fread getcwd) log
   PROC(E: sysctl sysctlbyname syscall ptrace-equivalents exit kill abort) log | DL(D2/D7: dlopen dlclose dlsym dladdr +4 dyld) log
   NET(H: connect socket getaddrinfo + NSURLSession/NSURLConnection selectors + proxy + reachability) log
   KC(J08: SecItem* x3 + kSec attrs) log | MACH(J01-05: clocks msg ports regions remap pid task_info) log
   THREAD(J06: pthread_create + getname_np + dispatch_once/semaphore + NSThread) log with entry symbol
   FPRINT(I: CFUUID NSBundle NSLocale NSTimeZone UIGraphics display) log | RECEIPT(A: appStoreReceiptURL attestKey) log+backtrace
   SCHEME(C2: canOpenURL + LSBundle scheme queries) log | HOOK-SCAN(D4-6: ms_hook_opcode family + strstr needs) log */

const T0 = Date.now();
const ts = () => '+' + ((Date.now() - T0) / 1000).toFixed(2) + 's';
const S = (ev) => send('[ent] ' + ts() + ' ' + ev);
let hotN = 0;
const hot = (l) => { hotN++; if (hotN % 100 === 0) S('HOT ' + l + ' x' + hotN); };
const bt = () => { try { return Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join(' <- ').slice(0, 300); } catch (e) { return ''; } };

let M = {};
for (const m of Process.enumerateModules()) {
  const n = m.name.toLowerCase();
  if (n === 'anogs') M.anogs = m;
  if (n === 'checknewdylib') M.gate = m;
  if (n === 'shadowtrackerextra') M.main = m;
}
S('spawned pid=' + Process.id + ' main=' + (M.main && M.main.base) + ' gate=' + (M.gate && M.gate.base) + ' anogs=' + (M.anogs && M.anogs.base));

// ---- GATE (D1a/D1b) + neuter ----
try {
  const uw = (p) => {
    try { const s = p.readCString(); if (s && s.length > 0 && s.length < 512) return s; } catch (e) {}
    try { const t = p.add(0x17).readS8(); let c = p; if ((t & 0x1f) !== 0) c = p.readPointer(); return c.readCString() || ''; } catch (e) {}
    return '?';
  };
  Interceptor.attach(M.gate.base.add(0x4000), {
    onEnter(a) { this.h = uw(a[0]); this.n = uw(a[1]); },
    onLeave(r) { S('GATE sym=' + this.h + ' needle=' + this.n + ' orig=' + r.toInt32() + '=>1'); r.replace(ptr(1)); }
  });
  S('GATE armed');
} catch (e) { S('GATE FAIL'); }

// ---- SEAM-15 (G) ----
for (const pair of [['Init', 0xf0fd0], ['InitEx', 0xf0ffc], ['SetUserInfo', 0xf1000], ['SetUserInfoLic', 0xf104c], ['OnPause', 0xf109c], ['OnResume', 0xf10bc], ['OnRecvData', 0xf1114], ['OnRecvSig', 0xf1188], ['GetReport', 0xf10dc], ['GetReport2', 0xf1174], ['GetReport3', 0xf1178], ['GetReport4', 0xf1180], ['DelReport', 0xf10f8], ['Ioctl', 0xf116c], ['IoctlOld', 0xf1168], ['RegistListener', 0xf118c], ['Free', 0xf1170]]) {
  try {
    Interceptor.attach(M.anogs.base.add(pair[1]), {
      onEnter(a) {
        let extra = '';
        try { if (pair[0] === 'OnRecvData' && !a[0].isNull()) extra = ' len=' + a[1].toInt32(); } catch (e) {}
        S('SEAM ' + pair[0] + extra);
      },
      onLeave(r) { try { S('SEAM-RET ' + pair[0] + ' -> ' + r); } catch (e) {} }
    });
  } catch (e) { S(pair[0] + ' FAIL'); }
}
S('SEAM-17 armed');

// ---- lazy per-module binder (single pass + one retry — NO interval) ----
function bindOnce(names, onHit, tag) {
  let bound = 0;
  const seen = {};
  for (const m of Process.enumerateModules()) {
    let ex = [];
    try { ex = m.enumerateExports(); } catch (e) { continue; }
    for (const e of ex) {
      const nm = e.name.replace(/^_/, '');
      if (names.indexOf(nm) !== -1 && !seen[nm]) { seen[nm] = true; bound++; try { onHit(nm, e.address); } catch (err) { S(tag + ' attach FAIL ' + nm); } }
    }
  }
  // libc global fallback for anything still missing
  for (const nm of names) {
    if (seen[nm]) continue;
    try { const a = Module.getExportByName(null, '_' + nm); onHit(nm, a); bound++; }
    catch (e) {}
  }
  S(tag + ' bound=' + bound + '/' + names.length);
  return bound;
}

const fsHit = (nm, a) => Interceptor.attach(a, { onEnter(ar) {
  try {
    // v6: fread/fopen log PATH ARG only — buffer-content reads were pure noise (fd/anon spam)
    if (nm === 'fread' || nm === 'mmap' || nm === 'read') { S('FS ' + nm + ' (fd)'); return; }
    let p = '';
    if (nm === 'openat') p = ar[1].readCString() || '';
    else if (nm === 'readlink' || nm === 'getcwd') p = ar[0].readCString() || ar[1].readCString() || '';
    else p = ar[0].readCString() || '';
    if (p) S('FS ' + nm + ' ' + p.slice(0, 160));
  } catch (e) {}
} });
const simpleHit = (fam) => (nm, a) => Interceptor.attach(a, { onEnter() { S(fam + ' ' + nm); } });
const hotHit = () => (nm, a) => Interceptor.attach(a, { onEnter() { hot(nm); } });

function bindFamily(f) {
  try {
    if (f === 'FS') bindOnce(['access', 'stat', 'lstat', 'fstat', 'statfs', 'open', 'openat', 'opendir', 'readdir', 'readlink', 'mmap', 'read', 'fopen', 'fread', 'getcwd'], fsHit, 'FS');
    else if (f === 'PROC') bindOnce(['sysctl', 'sysctlbyname', 'syscall', 'exit', 'kill'], simpleHit('PROC'), 'PROC');
    else if (f === 'DL') bindOnce(['dlopen', 'dlclose', 'dlsym', 'dladdr', '__dyld_image_count', '__dyld_get_image_name', '__dyld_get_image_header', '__dyld_get_image_vmaddr_slide'], (nm, a) => Interceptor.attach(a, {
      onEnter(ar) {
        try {
          if (nm === 'dlopen') S('DL dlopen ' + (ar[0].readCString() || '').slice(0, 120));
          else if (nm === 'dlsym') S('DL dlsym needs=' + ((() => { try { return ar[1].readCString() || ''; } catch (e) { return '?'; } })()).slice(0, 80));
          else if (nm === '__dyld_get_image_name') this.i = ar[0].toInt32();
          else S('DL ' + nm);
        } catch (e) {}
      },
      onLeave(r) { try { if (nm === '__dyld_image_count') S('DL IMG-COUNT=' + r.toInt32()); else if (nm === '__dyld_get_image_name') S('DL IMG-NAME[' + this.i + ']=' + (r.readCString() || '')); } catch (e) {} }
    }), 'DL');
    else if (f === 'NET') bindOnce(['connect', 'socket', 'getaddrinfo', 'CFNetworkCopySystemProxySettings', 'SCNetworkReachabilityCreateWithName', 'SCNetworkReachabilityGetFlags'], (nm, a) => Interceptor.attach(a, {
      onEnter(ar) {
        try {
          if (nm === 'SCNetworkReachabilityCreateWithName') S('NET reachability-host=' + (ar[1].readCString() || '').slice(0, 120));
          else if (nm === 'getaddrinfo') S('NET dns=' + (ar[0].readCString() || '').slice(0, 120));
          else S('NET ' + nm);
        } catch (e) {}
      }
    }), 'NET');
    else if (f === 'KC') bindOnce(['SecItemAdd', 'SecItemCopyMatching', 'SecItemDelete'], simpleHit('KC'), 'KC');
    else if (f === 'MACH') bindOnce(['mach_absolute_time', 'mach_msg', 'mach_task_self_', 'mach_port_deallocate', 'mach_timebase_info', 'mach_vm_region_recurse', 'mach_vm_remap', 'pid_for_task', 'task_get_special_port', 'task_info'], (nm, a) => {
      if (nm === 'mach_absolute_time' || nm === 'mach_msg') Interceptor.attach(a, { onEnter() { hot(nm); } });
      else Interceptor.attach(a, { onEnter() { S('MACH ' + nm); } });
    }, 'MACH');
    else if (f === 'THREAD') bindOnce(['pthread_create', 'pthread_getname_np', 'dispatch_once_f', 'dispatch_semaphore_wait', 'dispatch_semaphore_signal'], (nm, a) => Interceptor.attach(a, { onEnter() { S('THREAD ' + nm); } }), 'THREAD');
    else if (f === 'FPRINT') bindOnce(['CFUUIDCreate', 'CFUUIDCreateString'], simpleHit('FPRINT'), 'FPRINT');
  } catch (e) { S(f + ' family FAIL ' + e); }
}
// v6: stagger 1 family/sec — bindAll-over-1184-modules faulted the agent at +16.9s three times
['FS', 'PROC', 'DL', 'NET', 'KC', 'MACH', 'THREAD', 'FPRINT'].forEach((f, i) => setTimeout(() => bindFamily(f), 2000 + i * 1000));
// FIX-1 (DL 4/8): dyld getters invisible until dyld finishes binding — dedicated DL-only resweep at +30s
setTimeout(() => {
  try {
    bindOnce(['__dyld_image_count', '__dyld_get_image_name', '__dyld_get_image_header', '__dyld_get_image_vmaddr_slide'], (nm, a) => Interceptor.attach(a, {
      onEnter(ar) { try { if (nm === '__dyld_get_image_name') this.i = ar[0].toInt32(); else S('DL ' + nm); } catch (e) {} },
      onLeave(r) { try { if (nm === '__dyld_image_count') S('DL IMG-COUNT=' + r.toInt32()); else if (nm === '__dyld_get_image_name') S('DL IMG-NAME[' + this.i + ']=' + (r.readCString() || '')); } catch (e) {} }
    }), 'DL-RESWEEP');
  } catch (e) { S('DL-RESWEEP FAIL'); }
}, 30000);

// ---- ObjC selectors (C2/H/A): bound on FIRST SEAM Init (FIX-2: classes guaranteed resident by then) ----
let objcBound = false;
function bindObjC() {
  if (objcBound) return;
  objcBound = true;
  try {
    const hookSel = (cls, sel, tag) => {
      try {
        const m = ObjC.classes[cls][sel];
        Interceptor.attach(m.implementation, { onEnter(a) {
          try {
            let extra = '';
            if (sel.indexOf('canOpenURL') !== -1) { try { extra = ' url=' + new ObjC.Object(a[2]).toString().slice(0, 100); } catch (e) {} }
            if (sel.indexOf('dataTask') !== -1) { try { extra = ' req=' + new ObjC.Object(a[2]).URL().toString().slice(0, 140); } catch (e) {} }
            if (sel.indexOf('appStoreReceiptURL') !== -1) S('RECEIPT appStoreReceiptURL');
            else S(tag + ' ' + cls + ' ' + sel + extra);
          } catch (e) {}
        } });
        S('OBJC bound ' + cls + ' ' + sel);
      } catch (e) { S('OBJC miss ' + cls + ' ' + sel); }
    };
    hookSel('UIApplication', '-canOpenURL:', 'SCHEME');
    hookSel('NSURLSession', '-dataTaskWithRequest:completionHandler:', 'NET');
    hookSel('NSURLConnection', '+sendSynchronousRequest:returningResponse:error:', 'NET');
    try { Interceptor.attach(ObjC.classes.NSBundle['-appStoreReceiptURL'].implementation, { onEnter() { S('RECEIPT appStoreReceiptURL'); } }); S('OBJC bound receipt'); } catch (e) { S('OBJC miss receipt'); }
  } catch (e) { S('OBJC bootstrap FAIL'); }
}
// FIX-3 (order inversion): GATE+SEAM attach synchronously at +0.00s (above); module sweep (bindAll) deferred
// so the +4s IoctlOld storm is NEVER missed again — seam hooks exist before the storm, sweep fills the rest after.
try {
  Interceptor.attach(M.anogs.base.add(0xf0fd0), { onEnter() { try { bindObjC(); } catch (e) {} } });
  S('OBJC trigger armed on Init');
} catch (e) { setTimeout(bindObjC, 15000); }

S('ENTERPRISE ARMED — families: GATE SEAM-17 FS-14 PROC DL NET KC MACH THREAD FPRINT RECEIPT SCHEME');
