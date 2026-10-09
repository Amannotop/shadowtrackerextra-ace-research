'use strict';
// monitor.js — live anticheat-check monitor for ShadowTrackerExtra 4.6.0 (lab device ONLY)
// language: JavaScript, file: monitor.js, runtime: Frida 17.22.2 agent
// *watch for send()-only transport: console.log does NOT reach the python rig — every event uses send()*
/* Event taxonomy (which check is which):
   GATE      <- _CheckSymbolSource(symbol, needle) — per-symbol provenance (D1a/D1b blocklist pairs)
   DISPATCH  <- central 0x376a0 opcode 0..6 (one-shot flags — birth-capture only, attach within seconds)
   ENTER/LEAVE Init/SetUserInfo/OnPause/OnResume/OnRecvData/GetReport/DelReport/Ioctl — AnoSDK lifecycle seam
   FS        <- access/stat/lstat/open/openat/opendir/readlink path probes (B + C1)
   SYSCTL/SYSCALL <- debugger vectors (E1/E2) | IMG-COUNT <- enumeration (D2)
   KC        <- SecItem* identity ops (J08) | MACH <- clocks/ports/regions (J01..05) | THREAD <- watchdog births */

const T0 = Date.now();
const ts = () => '+' + ((Date.now() - T0) / 1000).toFixed(2) + 's';
const S = (ev) => send('[mon] ' + ts() + ' ' + ev);
let machCount = 0; // v3: hot-clock sample counter (1:100 — IPC choke fix)

let M = {};
try {
  for (const m of Process.enumerateModules()) {
    const n = m.name.toLowerCase();
    if (n === 'anogs') M.anogs = m;
    if (n === 'checknewdylib') M.gate = m;
    if (n === 'shadowtrackerextra') M.main = m;
  }
} catch (e) { send('[mon] MODENUM-FAIL ' + e); }
S('spawned pid=' + Process.id + ' main=' + (M.main && M.main.base) + ' gate=' + (M.gate && M.gate.base) + ' anogs=' + (M.anogs && M.anogs.base));

// GATE — the blocklist pairs live here (FIX-1: dual-convention unwrap — try char* first, SSO second)
let gateHits = 0;
try {
  const g = M.gate.base.add(0x4000);
  const uw = (p) => {
    try {
      // convention A: already-unwrapped char* (direct caller)
      try { const s = p.readCString(); if (s && s.length > 0 && s.length < 512) return s; } catch (e) {}
      // convention B: const std::string* with SSO tag byte +0x17 bit 0x1f (§4.1)
      try { const t = p.add(0x17).readS8(); let c = p; if ((t & 0x1f) !== 0) c = p.readPointer(); return c.readCString() || ''; } catch (e) {}
      // convention C: std::string* pointing at string object — dump first 64 bytes hex
      try { return 'hex:' + p.readByteArray(32).toString().slice(0, 64); } catch (e) {}
      return '?';
    } catch (e) { return '?'; }
  };
  Interceptor.attach(g, { onEnter(a) { this.h = uw(a[0]); this.n = uw(a[1]); }, onLeave(r) { gateHits++; S('GATE sym=' + this.h + ' needle=' + this.n + ' -> ' + r.toInt32()); } });
  S('gate hooked');
} catch (e) { S('gate hook FAIL ' + e); }

// DISPATCH order — one-shot, birth-capture only
try {
  const d = M.anogs.base.add(0x376a0);
  Interceptor.attach(d, { onEnter(a) { S('DISPATCH op=' + a[1].toInt32()); } });
  S('dispatch hooked');
} catch (e) { S('dispatch FAIL ' + e); }

// AnoSDK lifecycle seam
const SEAM = [['Init', 0xf0fd0], ['SetUserInfo', 0xf1000], ['OnPause', 0xf109c], ['OnResume', 0xf10bc], ['OnRecvData', 0xf1114], ['OnRecvSig', 0xf1188], ['GetReport', 0xf10dc], ['GetReport2', 0xf1174], ['GetReport3', 0xf1178], ['GetReport4', 0xf1180], ['DelReport', 0xf10f8], ['Ioctl', 0xf116c], ['IoctlOld', 0xf1168], ['RegistListener', 0xf118c]];
for (const pair of SEAM) {
  const nm = pair[0], off = pair[1];
  try {
    const a = M.anogs.base.add(off);
    Interceptor.attach(a, {
      onEnter() { S('ENTER ' + nm); },
      onLeave(r) { try { S('LEAVE ' + nm + ' -> ' + r); } catch (e) { S('LEAVE ' + nm); } }
    });
  } catch (e) { S(nm + ' FAIL'); }
}
S('seam hooked 14/14');

// FS probes verbatim
for (const n of ['access', 'stat', 'lstat', 'open', 'openat', 'opendir', 'readlink']) {
  try {
    const a = Module.getExportByName(null, '_' + n);
    Interceptor.attach(a, { onEnter(ar) { try { const i = (n === 'openat') ? 1 : 0; const p = ar[i].readCString() || ''; if (p) S('FS ' + n + ' ' + p); } catch (e) {} } });
  } catch (e) {}
}
S('fs hooked');

// debugger vectors + image + KC + Mach + threads (FIX-2: lazy per-module resolve — null-table at +0.00s misses them)
// resolved on first DISPATCH (link table populated by then), retried every 5s until all bound
const LAZY = [
  ['sysctl', null, 'SYSCTL'], ['syscall', null, 'SYSCALL'],
  ['__dyld_image_count', null, 'IMG'], ['__dyld_get_image_name', null, 'IMG'],
  ['SecItemAdd', null, 'KC'], ['SecItemCopyMatching', null, 'KC'], ['SecItemDelete', null, 'KC'],
  ['mach_absolute_time', null, 'MACH'], ['mach_msg', null, 'MACH'], ['pid_for_task', null, 'MACH'],
  ['mach_vm_region_recurse', null, 'MACH'], ['pthread_create', null, 'THREAD'], ['connect', null, 'NET'],
];
function lazyResolve() {
  for (const row of LAZY) {
    if (row[1] !== null) continue;
    const nm = row[0], fam = row[2];
    let addr = null;
    // per-module sweep: null-table misses early, per-module hits once dyld binds
    try {
      for (const m of Process.enumerateModules()) {
        try {
          const ex = m.enumerateExports().filter(e => e.name === '_' + nm || e.name === nm);
          if (ex.length > 0) { addr = ex[0].address; break; }
        } catch (e) {}
      }
      if (addr === null) addr = Module.getExportByName(null, (nm.startsWith('_') ? nm : '_' + nm));
    } catch (e) { continue; }
    if (addr === null) continue;
    row[1] = addr;
    try {
      if (nm === '__dyld_image_count') Interceptor.attach(addr, { onLeave(r) { try { S('IMG-COUNT=' + r.toInt32()); } catch (e) {} } });
      else if (nm === '__dyld_get_image_name') Interceptor.attach(addr, { onEnter(a) { this.i = a[0].toInt32(); }, onLeave(r) { try { S('IMG-NAME[' + this.i + ']=' + (r.readCString() || '')); } catch (e) {} } });
      else if (nm === 'syscall') Interceptor.attach(addr, { onEnter(a) { try { S('SYSCALL num=' + a[0].toInt32()); } catch (e) {} } });
      else if (nm === 'connect') Interceptor.attach(addr, { onEnter(a) { try { S('CONNECT fd=' + a[0].toInt32()); } catch (e) {} } });
      // v3 throttle: hot clocks sampled 1:100 (IPC choke killed birth-234300 at +1.57s); rare checks lossless
      else if (nm === 'mach_absolute_time' || nm === 'mach_msg') Interceptor.attach(addr, { onEnter() { try { machCount++; if (machCount % 100 === 0) S('MACH ' + nm + ' x' + machCount); } catch (e) {} } });
      else Interceptor.attach(addr, { onEnter() { S(fam + ' ' + nm); } });
      S('lazy-bound ' + nm + ' @ ' + addr);
    } catch (e) { S('lazy-attach FAIL ' + nm); row[1] = null; }
  }
  // v3: dyld-scope fallback — global table misses __dyld_* early; per-module dyld sweep hits
  try {
    const dyld = Process.getModuleByName('dyld');
    for (const row of LAZY) {
      if (row[1] !== null) continue;
      if (row[0] !== '__dyld_image_count' && row[0] !== '__dyld_get_image_name') continue;
      try {
        const ex = dyld.enumerateExports().filter(e => e.name === row[0]);
        if (ex.length > 0) {
          row[1] = ex[0].address;
          if (row[0] === '__dyld_image_count') Interceptor.attach(row[1], { onLeave(r) { try { S('IMG-COUNT=' + r.toInt32()); } catch (e) {} } });
          else Interceptor.attach(row[1], { onEnter(a) { this.i = a[0].toInt32(); }, onLeave(r) { try { S('IMG-NAME[' + this.i + ']=' + (r.readCString() || '')); } catch (e) {} } });
          S('dyld-bound ' + row[0] + ' @ ' + row[1]);
        }
      } catch (e) {}
    }
  } catch (e) {}
}
lazyResolve();
setTimeout(lazyResolve, 10000); // v4: single delayed retry — setInterval raced ACE image walk, killed agent +2.53s
S('lazy resolver armed (13 targets)');
S('monitor ARMED — drive: login->matchmaking->match-start->120s');
