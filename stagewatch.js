'use strict';
// stagewatch.js — report staging-file watcher (menu-only, no login, lab ONLY)
// watches open/stat/read on tss_ano.dat / tmp.xx.dat / ano_tmp + dumps first bytes on read
const S = (m) => send('[stage] ' + m);
const TARGETS = ['tss_ano.dat', 'tmp.xx.dat', 'ano_tmp', 'tersafe'];
for (const n of ['open', 'stat', 'lstat', 'fopen']) {
  try {
    Interceptor.attach(Module.getExportByName(null, '_' + n), {
      onEnter(a) {
        try {
          const p = a[0].readCString() || '';
          for (const t of TARGETS) if (p.indexOf(t) !== -1) S(n + ' ' + p);
        } catch (e) {}
      }
    });
  } catch (e) {}
}
try {
  Interceptor.attach(Module.getExportByName(null, '_read'), {
    onEnter(a) { this.fd = a[0].toInt32(); this.buf = a[1]; this.len = a[2].toInt32(); },
    onLeave(r) {
      try {
        const n = r.toInt32();
        if (n > 0 && n < 65536) {
          const b = this.buf.readByteArray(Math.min(n, 512));
          const u8 = new Uint8Array(b);
          let asc = '';
          for (let i = 0; i < u8.length; i++) asc += (u8[i] >= 32 && u8[i] < 127) ? String.fromCharCode(u8[i]) : '.';
          if (asc.indexOf('ano') !== -1 || asc.indexOf('sem_') !== -1 || asc.indexOf('vm_') !== -1 || asc.indexOf('report') !== -1 || asc.indexOf('tdm') !== -1)
            S('read-hit fd=' + this.fd + ' n=' + n + ' :: ' + asc.slice(0, 300));
        }
      } catch (e) {}
    }
  });
  S('read hooked');
} catch (e) { S('read FAIL'); }
S('STAGEWATCH ARMED — menu only');
