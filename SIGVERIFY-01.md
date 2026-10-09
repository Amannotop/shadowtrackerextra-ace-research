# SIGVERIFY-01.md — signature check is HASH-COMPARE, not RSA (KR, 2026-10-08)
**Method:** callee disassembly (`0x502b4` → `0xcb4a8/0xcbfe8/0xcc09c`), zero accounts.

## Chain
- `0xcb4a8`: bignum/bitstream init (loads 16 B const `@0x25ee50` — SHA init vector class).
- `0xcbfe8` + `0xcb5e4`: Merkle–Damgård block buffering (`0x38/0x40` = SHA-256 block geometry,
  `bzero` padding) — SHA-256 family.
- `0xcc09c`: hex-encodes 16 B via `%02x` loop (digest → hex string for `strcmp` vs `sig5`?).
- `0x50240` (called 2×): member lookup by name (w4/w5 flags = no-verify vs verify pass).

## Verdict
- NO 256 B RSA modulus hunt needed: `sig4`/`sig5` (256 B) most plausibly hold EXPECTED
  HEX DIGESTS (or digests + metadata), compared with `strcmp`-class `0x17470` against the
  computed hash. The "key" is a HASH, not a private key — so route-(b) = recompute digests
  over MODIFIED members and rewrite `sig4`/`sig5` consistently. No secret required.
- Test (menu-only, lab copy — NEVER the live bundle): patch one byte of a COPY's `comm.dat`
  member, recompute SHA-256, rewrite `sig5`, run verify `0x502b4` via Frida, expect `0x0`.
  PASS = full route-(b) forge proven without any key.
