'use strict';
// hook_advanced.js — preemptive coverage mirror: EVERY hook logs hits, proving coverage even with zero kills
// language: JavaScript, file: hook_advanced.js, runtime: Frida 17.22.2 (lab device ONLY)
// *watch for proof inversion: hook-hit log IS the coverage proof — silence + hits = bypassed; silence + no hits = untested path*
// *watch for G-6: gate neuter armed first; all other hooks log-only in this mirror (spoof lives in bypass_advanced.x)*
const HITS = {};
const hit = (id) => { HITS[id] = (HITS[id] || 0) + 1; send('[hit] ' + id + ' x' + HITS[id]); };
const V = (...a) => send('[adv] ' + a.join(' '));

let M = {};
for (const m of Process.enumerateModules()) {
  const n = m.name.toLowerCase();
  if (n === 'anogs') M.anogs = m;
  if (n === 'checknewdylib') M.gate = m;
  if (n === 'shadowtrackerextra') M.main = m;
}
V('bases main=' + (M.main && M.main.base) + ' gate=' + (M.gate && M.gate.base) + ' anogs=' + (M.anogs && M.anogs.base));

// HOOK-D-01 first (gate neuter + hit log)
try {
  Interceptor.attach(M.gate.base.add(0x4000), {
    onEnter(a) {
      try {
        const uw = (p) => { try { const s = p.readCString(); if (s && s.length < 512) return s; } catch (e) {} try { const t = p.add(0x17).readS8(); let c = p; if ((t & 0x1f) !== 0) c = p.readPointer(); return c.readCString() || ''; } catch (e) {} return '?'; };
        this.h = uw(a[0]); this.n = uw(a[1]);
      } catch (e) {}
    },
    onLeave(r) { hit('DET-D-01 gate sym=' + this.h + ' needle=' + this.n + ' orig=' + r.toInt32() + '=>1'); r.replace(ptr(1)); }
  });
  V('D-01 armed');
} catch (e) { V('D-01 FAIL'); }

// AnoSDK seam hit log (G-family coverage)
for (const pair of [['Init', 0xf0fd0], ['SetUserInfo', 0xf1000], ['OnRecvData', 0xf1114], ['GetReport', 0xf10dc], ['GetReport2', 0xf1174], ['Ioctl', 0xf116c], ['IoctlOld', 0xf1168]]) {
  try {
    Interceptor.attach(M.anogs.base.add(pair[1]), {
      onEnter() { hit('DET-G ' + pair[0]); },
    });
  } catch (e) {}
}
V('G-seam armed');

// fs / sysctl / image hit logs (B/C/D-02/E coverage)
for (const n of ['access', 'stat', 'lstat', 'open']) {
  try {
    Interceptor.attach(Module.getExportByName(null, '_' + n), {
      onEnter(a) { try { const p = a[0].readCString() || ''; if (p) hit('DET-B/C fs:' + n + ' ' + p.slice(0, 120)); } catch (e) {} }
    });
  } catch (e) {}
}
try { Interceptor.attach(Module.getExportByName(null, 'sysctl'), { onEnter() { hit('DET-E-01 sysctl'); } }); } catch (e) {}
try { Interceptor.attach(Module.getExportByName(null, '__dyld_image_count'), { onEnter() { hit('DET-D-02 imgcount'); } }); } catch (e) {}
for (const n of ['SecItemAdd', 'SecItemCopyMatching', 'SecItemDelete']) {
  try { Interceptor.attach(Module.getExportByName(null, '_' + n), { onEnter() { hit('DET-J-08 KC:' + n); } }); } catch (e) {}
}
V('coverage mirror ARMED — every check that fires leaves a [hit] line');
