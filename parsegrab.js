'use strict';
// parsegrab.js — comm parse-output + sig-verify arg capture (menu-only, NO login, lab ONLY)
// targets (KR anogs, slide-independent via export-relative? NO — absolute file-offsets + live base):
//   0xeed68 parse-A out, 0x502b4 sigverify args, 0x17470 tlf-check. Add live anogs base at runtime.
const S = (m) => send('[parse] ' + m);
const anogs = Process.getModuleByName('anogs');
S('anogs=' + anogs.base);
const at = (off) => anogs.base.add(off);
const hex = (p, n) => {
  try {
    const b = p.readByteArray(Math.min(n, 256));
    if (!b) return '?';
    return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('').slice(0, 160);
  } catch (e) { return 'ERR'; }
};
try {
  Interceptor.attach(at(0xeed68), {
    onEnter(a) { this.a0 = a[0]; this.a1 = a[1]; S('eed68-enter a0=' + a[0] + ' a1=' + a[1]); },
    onLeave(r) { S('eed68-leave -> ' + r + ' in0=' + hex(this.a0, 64)); }
  });
  S('eed68 hooked');
} catch (e) { S('eed68 FAIL ' + e); }
try {
  Interceptor.attach(at(0x502b4), {
    onEnter(a) {
      let s = '';
      try { s = ' x1=' + a[1].readCString() + ' x3=' + a[3].readCString(); } catch (e) {}
      S('sigverify-enter' + s);
      try { S('sigverify-x0=' + hex(a[0], 64) + ' x2=' + hex(a[2], 64)); } catch (e) {}
    },
    onLeave(r) { S('sigverify-leave -> ' + r); }
  });
  S('sigverify hooked');
} catch (e) { S('sigverify FAIL ' + e); }
try {
  Interceptor.attach(at(0x17470), {
    onEnter(a) { try { S('tlfcheck s=' + a[1].readCString()); } catch (e) {} }
  });
  S('tlfcheck hooked');
} catch (e) { S('tlfcheck FAIL ' + e); }
S('PARSEGRAB ARMED — menu only');
