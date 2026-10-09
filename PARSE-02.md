# PARSE-02.md — sig-verify ABI resolved (KR menu-only, PID 69297, 2026-10-08)
**Log:** `captures/parse2-*/parse2.log`.

## ABI: `0x502b4(name, zipdata, ziplen, member, signame, outbuf)`
- `x0`=`"comm.zip"`, `x1`=ZIP bytes (`PK\x03\x04`), `x2`=`0xFD8`=4056 = LENGTH (not a pointer —
  first run misread it; constant across calls), `x3`=`"comm.dat"`, `x4`=`"sig5"`, `x5`=out buffer.
- Returns `0x0` (PASS) on clean boot, both call batches (+3 s, +8 s).
- Key location: NOT in args — embedded inside `0x502b4` (or fetched internally). Next static
  cut: disassemble `0x502b4` internals (RSA verify = modular exponentiation shape; key =
  256 B modulus in `__const` or Keychain item or server blob).

## Standing
Route-(b) key hunt narrowed to ONE function body. Route-(a) unaffected (needs no key).
