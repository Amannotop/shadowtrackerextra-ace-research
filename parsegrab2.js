'use strict';
// parsegrab2.js — key-operand wide read + eed68 output structs (menu-only, NO login)
const S = (m) => send('[p2] ' + m);
const anogs = Process.getModuleByName('anogs');
const at = (off) => anogs.base.add(off);
const hexd = (p, n) => {
  try {
    const b = p.readByteArray(n);
    if (!b) return 'unreadable';
    return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
  } catch (e) { return 'ERR:' + e; }
};
const cstr = (p) => { try { return p.readCString() || ''; } catch (e) { return 'ERR'; } };
Interceptor.attach(at(0x502b4), {
  onEnter(a) {
    this.x0 = a[0]; this.x1 = a[1]; this.x2 = a[2]; this.x3 = a[3]; this.x4 = a[4]; this.x5 = a[5];
    S('sig-x0=' + cstr(a[0]).slice(0,60) + ' x1=' + cstr(a[1]).slice(0,60) + ' x3=' + cstr(a[3]).slice(0,60) + ' x4=' + cstr(a[4]).slice(0,60));
    S('sig-x2-ptr=' + a[2] + ' x5=' + a[5]);
  },
  onLeave(r) {
    S('sig-ret=' + r);
    try {
      // x2 wide: try as pointer-to-struct then raw bytes
      const p = this.x2;
      S('x2-as-cstr=' + cstr(p).slice(0,80));
      S('x2-bytes=' + hexd(p, 128).slice(0,200));
      // if x2 points to struct with pointers, dump first two pointees
      try {
        const q0 = p.readPointer(), q1 = p.add(Process.pointerSize).readPointer();
        S('x2-p0=' + hexd(q0, 64).slice(0,120) + ' p1=' + hexd(q1, 64).slice(0,120));
      } catch (e) { S('x2-deref-none'); }
    } catch (e) { S('x2-wide-ERR'); }
  }
});
S('P2 ARMED — menu only');
