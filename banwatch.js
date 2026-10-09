'use strict';
// banwatch.js — 10000000x conviction monitor for guest match (lab device ONLY)
// GOAL: capture the exact check + verdict + buffer that convicts, with timestamps.
// Watches: GATE pairs+verdicts | dispatcher ops | GetReport* buffers (hash+verdict region) |
//   OnRecvData (server challenge/response = ban arrival?) | Ioctl/IoctlOld | THREAD births |
//   KC ops | sysctl/ptrace | _exit/_kill (local-kill proof) | heartbeat 0x1e cadence.
// RULES: log-only (NO spoof — this run is diagnosis, not bypass). Sample hot clocks, lossless rare.
const T0 = Date.now();
const ts = () => '+' + ((Date.now() - T0) / 1000).toFixed(2) + 's';
const S = (m) => send('[ban] ' + ts() + ' ' + m);
let hotN = 0;
const hot = (l) => { hotN++; if (hotN % 200 === 0) S('HOT ' + l + ' x' + hotN); };

let M = {};
for (const m of Process.enumerateModules()) {
  const n = m.name.toLowerCase();
  if (n === 'anogs') M.anogs = m;
  if (n === 'checknewdylib') M.gate = m;
  if (n === 'shadowtrackerextra') M.main = m;
}
S('bases main=' + (M.main && M.main.base) + ' gate=' + (M.gate && M.gate.base) + ' anogs=' + (M.anogs && M.anogs.base));

// GATE with verdicts (THE conviction candidates)
try {
  const uw = (p) => {
    try { const s = p.readCString(); if (s && s.length > 0 && s.length < 256) return s; } catch (e) {}
    try { const t = p.add(0x17).readS8(); let c = p; if ((t & 0x1f) !== 0) c = p.readPointer(); return c.readCString() || ''; } catch (e) {}
    return '?';
  };
  Interceptor.attach(M.gate.base.add(0x4000), {
    onEnter(a) { this.h = uw(a[0]); this.n = uw(a[1]); },
    onLeave(r) { const v = r.toInt32(); S('GATE sym=' + this.h + ' needle=' + this.n + ' -> ' + v + (v !== 1 ? ' <<<< DIRTY' : '')); }
  });
  S('gate armed');
} catch (e) { S('gate FAIL'); }

// dispatcher + seam with args
try {
  Interceptor.attach(M.anogs.base.add(0x376a0), { onEnter(a) { S('DISPATCH op=' + a[1].toInt32()); } });
  S('dispatch armed');
} catch (e) {}
const SEAM = [['Init',0xf0fd0],['SetUserInfo',0xf1000],['SetUserInfoLic',0xf104c],['OnPause',0xf109c],['OnResume',0xf10bc],['OnRecvData',0xf1114],['OnRecvSig',0xf1188],['GetReport',0xf10dc],['GetReport2',0xf1174],['GetReport3',0xf1178],['GetReport4',0xf1180],['DelReport',0xf10f8],['DelReport3',0xf117c],['DelReport4',0xf1184],['Ioctl',0xf116c],['IoctlOld',0xf1168],['RegistListener',0xf118c]];
for (const [nm, off] of SEAM) {
  try {
    Interceptor.attach(M.anogs.base.add(off), {
      onEnter(a) {
        let x = '';
        try {
          if (nm === 'OnRecvData' && !a[0].isNull()) {
            x = ' len=' + a[1].toInt32();
            const b = a[0].readByteArray(Math.min(a[1].toInt32(), 256));
            if (b) x += ' head=' + Array.from(new Uint8Array(b)).map(c => c.toString(16).padStart(2,'0')).join('').slice(0,96);
          }
        } catch (e) {}
        S('SEAM ' + nm + x);
      },
      onLeave(r) {
        try {
          // GetReport*: hash first 256B + dump verdict-candidate region
          const s = nm.indexOf('GetReport') === 0 ? (function () {
            try {
              if (r.isNull()) return ' NULL';
              const b = r.readByteArray(256);
              const u = new Uint8Array(b);
              let h = 0; for (const c of u) h = ((h << 5) - h + c) | 0;
              let asc = '';
              for (const c of u) asc += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
              return ' bufhash=' + (h >>> 0).toString(16) + ' ascii=' + asc.slice(0, 120);
            } catch (e) { return ' unreadable'; }
          })() : ' -> ' + r;
          S('SEAM-RET ' + nm + s);
        } catch (e) {}
      }
    });
  } catch (e) { S(nm + ' FAIL'); }
}
S('seam-18 armed');

// local-kill proof (_exit/_kill with caller)
for (const n of ['_exit', '_kill']) {
  try {
    Interceptor.attach(Module.getExportByName(null, n), {
      onEnter(a) { S('KILL ' + n + ' arg0=' + a[0] + ' <<<< LOCAL-KILL'); }
    });
    S(n + ' armed');
  } catch (e) { S(n + ' miss'); }
}
// lazy per-module bind, staggered (v6 rule)
function bindOnce(names, fn, tag) {
  let n = 0;
  for (const m of Process.enumerateModules()) {
    let ex = [];
    try { ex = m.enumerateExports(); } catch (e) { continue; }
    for (const e of ex) {
      const nm = e.name.replace(/^_/, '');
      if (names.indexOf(nm) !== -1 && !e._b) { e._b = true; n++; try { fn(nm, e.address); } catch (err) {} }
    }
  }
  S(tag + ' bound=' + n);
}
const FAMS = [
  ['FS', ['access','stat','lstat','open','openat']],
  ['PROC', ['sysctl','sysctlbyname','syscall']],
  ['DL', ['dlopen','dlsym','dladdr','__dyld_image_count','__dyld_get_image_name']],
  ['KC', ['SecItemAdd','SecItemCopyMatching','SecItemDelete']],
  ['MACH', ['mach_absolute_time','mach_msg','pid_for_task','mach_vm_region_recurse']],
  ['THREAD', ['pthread_create']],
  ['NET', ['connect','getaddrinfo']],
];
FAMS.forEach(([tag, names], i) => setTimeout(() => bindOnce(names, (nm, a) => {
  if (nm === 'mach_absolute_time' || nm === 'mach_msg') Interceptor.attach(a, { onEnter() { hot(nm); } });
  else if (nm === '__dyld_get_image_name') Interceptor.attach(a, { onEnter(x) { this.i = x[0].toInt32(); }, onLeave(r) { try { const s = r.readCString() || ''; if (/frida|gum|substrate|shadow|inject|libhook/i.test(s)) S('DL SUSPICIOUS-IMG[' + this.i + ']=' + s); } catch (e) {} } });
  else Interceptor.attach(a, { onEnter() { S(tag + ' ' + nm); } });
}, tag), 2000 + i * 1000));
S('BANWATCH ARMED — log-only, play now, report ban text the second it lands');
