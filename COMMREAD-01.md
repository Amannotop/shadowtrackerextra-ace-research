# COMMREAD-01.md — comm.dat load/verify/parse chain (KR, 2026-10-08)
**Method:** literal-pool xref (`comm.dat` ×2, `tlf`, `sig5`, `tmp.xx.dat`), zero accounts.

## Chain (3 sites)
1. **Boot loader `0x4e24`**: `bl 0xad2cc; x1="comm.dat"; bl 0xae7e4` (load), result folded
   into a bitmask accumulator (`w19 |= 0x80000` on success path via `csel`).
   Context: chained `bl 0x84e50 / 0xd2e7c / 0x6996c / vtable+0x28 / 0x8556c` init sequence —
   comm load is one bit among many (`0x8000/0x10000/0x20000/0x80000` flags). Boot-health
   bitmask: each subsystem sets its bit; missing bit = subsystem failed. NEW hook surface
   (DET-G-09 init-bitmask: spoof individual bits without touching others).
2. **Verify+parse `0xa34f0`** (the security path): `0xad2cc` alloc → `0xae7e4` load →
   `0xa3580` open-check → `ldp x1,x2,[x0,#0x40]` (buffer+len from object) →
   `x3="comm.dat", x4="sig5", bl 0x502b4` (**signature verification**, `-1` on fail) →
   `0xeed68 / 0xeed70` (parse pair) → size/`0xf` check (`csetm w0,lo`, `-2` on fail).
   **This is the load-bearing chain:** `0x502b4` = sig-verify, `0xeed68/70` = TLV parse.
   Hook candidates: `0x502b4`-force-pass (sig bypass — test-only, menu-only) or
   `0xeed68`-output capture (plaintext records post-parse — the cipher dies HERE).
3. **`tlf` check `0xa3a88`**: `bl 0xef8a0 / 0xefb10` (buffer prep) → `x1="tlf"` →
   `bl 0x17470` (magic compare). Magic gate before parse.
4. **`tmp.xx.dat` writer `0x99038`** (site 152492): `add x22,x22,#0xc65 "tmp.xx.dat"` —
   staging writer found; caller chain = report-flush path (Phase-4 hop candidate).

## Owned next (menu-only, no account)
- `0xeed68`-output capture (Frida `onLeave`: dump parsed-record buffer — plaintext names?).
- `0x502b4` arg capture (which key? key bytes = §16.4 route-(b) material — log-only first).
- `0x4e24`-bitmask transcript (which bits set on clean boot = init-health baseline).
