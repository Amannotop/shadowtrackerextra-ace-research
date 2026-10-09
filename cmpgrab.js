'use strict';
// cmpgrab.js — comparator both-operand dump (menu-only, NO login)
const S = (m) => send('[cmp] ' + m);
const anogs = Process.getModuleByName('anogs');
const at = (off) => anogs.base.add(off);
const hx = (p, n) => {
  try {
    const b = p.readByteArray(n);
    if (!b) return 'unreadable';
    const h = Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
    let asc = '';
    for (const x of new Uint8Array(b)) asc += (x >= 32 && x < 127) ? String.fromCharCode(x) : '.';
    return h.slice(0,128) + ' |' + asc.slice(0,64);
  } catch (e) { return 'ERR'; }
};
let n = 0;
Interceptor.attach(at(0x17470), {
  onEnter(a) {
    if (n++ > 40) return;
    this.r = [a[0], a[1], a[2], a[3]];
    S('call a0=' + a[0] + ' a1=' + a[1] + ' a2=' + a[2] + ' a3=' + a[3]);
  },
  onLeave(r) {
    if (n > 41) return;
    try {
      const [a0, a1, a2, a3] = this.r;
      S('ret=' + r + ' A=' + hx(a0, 64) + ' B=' + hx(a1, 64));
    } catch (e) {}
  }
});
S('CMPGAB ARMED — menu only');
