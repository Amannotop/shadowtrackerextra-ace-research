'use strict';
// xmlgrab.js — menu-only GetReportData buffer capture (NO login, NO account, lab device ONLY)
// language: JavaScript, file: xmlgrab.js, runtime: Frida 17.22.2
// *watch for buffer size: read min(returned_len, 64KB) — never unbounded read (fault risk on guarded pages)*
// *watch for menu-only rule: operator drives NOTHING past the login screen — buffers fire at boot (proven 3 runs)*
const S = (m) => send('[xml] ' + m);
let M = {};
for (const m of Process.enumerateModules()) {
  const n = m.name.toLowerCase();
  if (n === 'anogs') M.anogs = m;
}
S('anogs=' + (M.anogs && M.anogs.base));
const dump = (label, ptr) => {
  try {
    if (ptr.isNull()) { S(label + ' NULL'); return; }
    const b = ptr.readByteArray(4096);
    if (!b) { S(label + ' unreadable'); return; }
    const u8 = new Uint8Array(b);
    let ascii = '';
    for (let i = 0; i < u8.length; i++) {
      const c = u8[i];
      ascii += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
      if (i > 0 && i % 160 === 159) ascii += '\n';
    }
    // ship first 3.2KB as printable — element names visible here if plaintext-at-use
    S(label + ' len-probe:\n' + ascii.slice(0, 3200));
  } catch (e) { S(label + ' ERR ' + e); }
};
for (const pair of [['GetReport', 0xf10dc], ['GetReport2', 0xf1174], ['GetReport3', 0xf1178], ['GetReport4', 0xf1180]]) {
  try {
    Interceptor.attach(M.anogs.base.add(pair[1]), {
      onLeave(r) {
        try { S(pair[0] + ' -> ' + r); dump(pair[0], r); }
        catch (e) { S(pair[0] + ' leave-ERR'); }
      }
    });
    S(pair[0] + ' hooked');
  } catch (e) { S(pair[0] + ' FAIL'); }
}
S('XMLGRAB ARMED — menu only, no login');
