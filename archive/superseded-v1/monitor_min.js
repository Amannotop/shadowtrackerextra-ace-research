'use strict';
// monitor_min.js — v5 minimal birth monitor: seam + gate + fs ONLY (lab device ONLY)
// language: JavaScript, file: monitor_min.js, runtime: Frida 17.22.2 agent
// *watch for agent-death: full monitor dies ~+1.6s (process lives) — suspect pthread/Mach hooks in loader lock*
// v5: NO sysctl/syscall/mach/thread/connect/keychain/dyld hooks. Pass = survive past +4s IoctlOld storm.
const T0 = Date.now();
const ts = () => '+' + ((Date.now() - T0) / 1000).toFixed(2) + 's';
const S = (ev) => send('[mon] ' + ts() + ' ' + ev);

let M = {};
for (const m of Process.enumerateModules()) {
  const n = m.name.toLowerCase();
  if (n === 'anogs') M.anogs = m;
  if (n === 'checknewdylib') M.gate = m;
  if (n === 'shadowtrackerextra') M.main = m;
}
S('spawned pid=' + Process.id + ' main=' + (M.main && M.main.base) + ' gate=' + (M.gate && M.gate.base) + ' anogs=' + (M.anogs && M.anogs.base));

try {
  const g = M.gate.base.add(0x4000);
  const uw = (p) => {
    try { const s = p.readCString(); if (s && s.length > 0 && s.length < 512) return s; } catch (e) {}
    try { const t = p.add(0x17).readS8(); let c = p; if ((t & 0x1f) !== 0) c = p.readPointer(); return c.readCString() || ''; } catch (e) {}
    return '?';
  };
  Interceptor.attach(g, { onEnter(a) { this.h = uw(a[0]); this.n = uw(a[1]); }, onLeave(r) { S('GATE sym=' + this.h + ' needle=' + this.n + ' -> ' + r.toInt32()); } });
  S('gate hooked');
} catch (e) { S('gate FAIL ' + e); }

try {
  Interceptor.attach(M.anogs.base.add(0x376a0), { onEnter(a) { S('DISPATCH op=' + a[1].toInt32()); } });
  S('dispatch hooked');
} catch (e) { S('dispatch FAIL ' + e); }

const SEAM = [['Init', 0xf0fd0], ['InitEx', 0xf0ffc], ['SetUserInfo', 0xf1000], ['OnPause', 0xf109c], ['OnResume', 0xf10bc], ['OnRecvData', 0xf1114], ['OnRecvSig', 0xf1188], ['GetReport', 0xf10dc], ['GetReport2', 0xf1174], ['GetReport3', 0xf1178], ['GetReport4', 0xf1180], ['DelReport', 0xf10f8], ['Ioctl', 0xf116c], ['IoctlOld', 0xf1168], ['RegistListener', 0xf118c]];
for (const pair of SEAM) {
  try {
    Interceptor.attach(M.anogs.base.add(pair[1]), {
      onEnter() { S('ENTER ' + pair[0]); },
      onLeave(r) { try { S('LEAVE ' + pair[0] + ' -> ' + r); } catch (e) { S('LEAVE ' + pair[0]); } }
    });
  } catch (e) { S(pair[0] + ' FAIL'); }
}
S('seam hooked');

// fs probes verbatim (narrow, low-rate — safe)
for (const n of ['access', 'stat', 'lstat', 'open', 'openat', 'opendir', 'readlink']) {
  try {
    const a = Module.getExportByName(null, '_' + n);
    Interceptor.attach(a, { onEnter(ar) { try { const i = (n === 'openat') ? 1 : 0; const p = ar[i].readCString() || ''; if (p) S('FS ' + n + ' ' + p); } catch (e) {} } });
  } catch (e) {}
}
S('v5-min ARMED — pass = survive past +4s storm');
