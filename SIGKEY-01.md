# SIGKEY-01.md — verify-key hunt status (KR, 2026-10-08)
**Method:** import census + callee-shape analysis, zero accounts.

## Narrowed shape
- `sig5` = 256 B random = RSA-2048 signature. NO crypto imports anywhere
  (`SecKey/RSA/CC/HMAC/SSL`: zero in BOTH variants' U-lists) → **in-house RSA**.
- Verify chain: SHA-256-style hash (`0xcbfe8` block buffering) + bignum init (`0xcb4a8`)
  + 16 B hex print (`0xcc09c`) + `strcmp`-class compare (`0x17470`).
- Missing: the modexp + modulus. `0xcb4a8`'s only const is 16 B (`@0x25ee50` = hash IV class),
  NOT a 256 B modulus. Entropy scan of `__const` (11,978 words): 8,709 high-entropy 256 B
  windows — too noisy (compressed blobs + code). Modulus hunt by entropy alone REJECTED.

## Next (static, owned)
- Find the modexp loop by SHAPE: square-and-multiply = distinctive `mul`/`umulh` chains with
  4×64-bit limbs (2048-bit = 32×64-bit words; look for 32-iteration counted loops near the
  `0xcb*` family). The modulus sits within ±4 KB of that loop (arm64 adrp range).
- Exponent check: `0x10001` (65537) immediate or 3 B const nearby = RSA confirm.
- Owner: next static cut. Route-(a) unaffected (needs no key); route-(b) blocked on this item.
