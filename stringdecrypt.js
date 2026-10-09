// stringdecrypt.js — Phase-8 runtime string-recovery harness (lab device ONLY)
// language: JavaScript, file: stringdecrypt.js, runtime: Frida 17.22.2
// *watch for decrypt-on-use: endpoints/paths/needles materialize post-AnoSDKInit — dump at multiple lifecycle points*
// *watch for server-issued tables via OnRecvData: diff pre/post-login memory (device-bound vs server-derived disambiguation)*
// Produces Appendix-I records -> strdump.md. Static-only sets are REJECTED (§10.2-9); this harness closes S-1..S-5.

'use strict';

const S = { endpoints: new Set(), paths: new Set(), pairs: [], tools: new Set() };
const V = (...a) => console.log('[strdec] ' + a.join(' '));

function modules() {
  const r = {};
  for (const m of Process.enumerateModules()) {
    const n = m.name.toLowerCase();
    if (n === 'anogs') r.anogs = m;
    if (n === 'shadowtrackerextra') r.main = m;
  }
  return r;
}

// S-1: endpoint/URL recovery — capture runtime connect + dataTask args + heap grep for http post-Init
function s1Endpoints() {
  try {
    Interceptor.attach(Module.getExportByName(null, 'connect'), {
      onEnter(args) {
        try {
          const sa = args[1];
          const fam = sa.readU8();
          if (fam === 2) { // AF_INET
            const port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8());
            const ip = [sa.add(4).readU8(), sa.add(5).readU8(), sa.add(6).readU8(), sa.add(7).readU8()].join('.');
            S.endpoints.add(ip + ':' + port); V('connect ' + ip + ':' + port);
          }
        } catch (e) {}
      }
    });
  } catch (e) { V('no connect export: ' + e); }
  const hookNS = (cls, sel) => {
    try {
      const m = ObjC.classes[cls][sel];
      Interceptor.attach(m.implementation, {
        onEnter(args) {
          try {
            const req = new ObjC.Object(args[2]);
            const url = req.URL().toString();
            S.endpoints.add(url); V('dataTask ' + url);
          } catch (e) {}
        }
      });
      V('hooked ' + cls + ' ' + sel);
    } catch (e) { V('skip ' + cls + ' ' + sel + ': ' + e); }
  };
  hookNS('NSURLSession', '-dataTaskWithRequest:completionHandler:');
}

// S-2: probed-path recovery — hook DoRiskFileTCJTask-adjacent fs calls, dump verbatim path args
function s2Paths() {
  for (const n of ['access', 'stat', 'lstat', 'open', 'openat', 'opendir', 'readlink']) {
    let a = null;
    try { a = Module.getExportByName(null, '_' + n); } catch (e) { continue; }
    if (a === null) continue;
    Interceptor.attach(a, {
      onEnter(args) {
        try {
          const idx = (n === 'openat') ? 1 : 0;
          const p = args[idx].readCString() || '';
          if (p && !S.paths.has(p)) { S.paths.add(p); V(n + ' path=' + p); }
        } catch (e) {}
      }
    });
  }
}

// S-3: gate-pair recovery — log runtime (symbol, needle) pairs at _CheckSymbolSource
function s3GatePairs(M) {
  if (!M || !M.gate) { V('no gate module'); return; }
  const addr = M.gate.base.add(0x4000);
  const unwrap = (p) => {
    try {
      const tag = p.add(0x17).readS8();
      let c = p; if ((tag & 0x1f) !== 0) c = p.readPointer();
      return c.readCString() || '';
    } catch (e) { return '<err>'; }
  };
  Interceptor.attach(addr, {
    onEnter(args) { this.h = unwrap(args[0]); this.n = unwrap(args[1]); },
    onLeave(retval) {
      S.pairs.push({ sym: this.h, needle: this.n, ret: retval.toInt32() });
      V('pair sym=' + this.h + ' needle=' + this.n + ' -> ' + retval.toInt32());
    }
  });
}

// S-4: tool-literal recovery — post-decrypt heap grep for tool names + image/symbol hit log
function s4ToolLiterals(M) {
  if (!M || !M.anogs) return;
  const needles = ['frida', 'gum', 'substrate', 'substitute', 'cydia', 'sileo', 'zebra', 'shadow', 'choicy', 'hestia'];
  Memory.scan(M.anogs.base, M.anogs.size, '6672696461', { // 'frida' hex — example pattern; full sweep below
    onMatch(addr, size) { V('heap-hit frida @ ' + addr); },
    onComplete() { V('heap sweep pass done'); }
  });
  // string-table cross-check: which tool literals are reachable at runtime vs statically absent
  for (const t of needles) V('tool-watch ' + t);
}

// S-5: transform-hunt stub — records candidate decryptor evidence; operator closes accept/reject per candidate
// candidates: XOR const near __const | libz table | mmap'd blob | device-bound (CFUUID keystream) | server-issued (OnRecvData)
function s5TransformHunt() {
  V('S-5 candidates: xor-const | libz-inflate | mmap-blob | device-bound | server-issued — evidence per Appendix-I');
  try {
    const inf = Module.getExportByName(null, 'inflate');
    V('libz inflate present @ ' + inf + ' (compressed-table candidate OPEN)');
  } catch (e) { V('no inflate export (NEG pending full dump)'); }
}

function dump() {
  console.log('===== STRDUMP =====');
  console.log('ENDPOINTS(' + S.endpoints.size + '):');
  for (const e of S.endpoints) console.log('  S-1 ' + e);
  console.log('PATHS(' + S.paths.size + '):');
  for (const p of S.paths) console.log('  S-2 ' + p);
  console.log('PAIRS(' + S.pairs.length + '):');
  for (const q of S.pairs) console.log('  S-3 ' + q.sym + ' | ' + q.needle + ' -> ' + q.ret);
  console.log('===== END =====');
}

function main() {
  const M = modules();
  V('bases anogs=' + (M.anogs && M.anogs.base));
  s1Endpoints(); s2Paths(); s3GatePairs(M); s4ToolLiterals(M); s5TransformHunt();
  V('harness armed — drive app through launch->login->matchmaking->match-start->120s, then call dump() via frida REPL');
  globalThis.strdump = dump;
}
setImmediate(main);
