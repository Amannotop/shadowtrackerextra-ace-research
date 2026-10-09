# COMM-01.md — comm.dat shipped vs live (KR, 2026-10-08)
**Files:** `ano_tmp/comm.zip` (shipped Nov 2025: `comm.dat` 5796 B + `sig4`/`sig5` 256 B each)
vs live `ano_tmp/comm.dat` (2705 B, today's run).

## Structure (both)
- Magic `00 00 00 03 'tlf' 00`, then records. Shipped parse walks cleanly as
  `[tag:u16][len:u16][payload]`; live file's second record overshoots under that parse —
  live uses a variant framing (length includes nested headers, or post-`Init` mutation).
- Record payloads = obfuscated record-names (printable high-entropy ascii:
  `qRFZBTBXJ`, `wP_VdYWN]K`, …). Single-byte XOR (all 256 keys) + ROT47: NO plaintext.
  Cipher = multi-byte/rolling (`tcj_encrypt` family) — runtime decryptor required (Phase 8).

## Signatures (`sig4`, `sig5` — 256 B each = RSA-2048 class)
- Shipped bundle is SIGNED. Verification key location: unknown (binary? Keychain? server?).
- Forgery route (b) needs key+algo+order byte-proven — currently 0/3. Route (a)
  (pre-serializer zeroing, authentic signing preserved) stays the ONLY viable route.

## Deltas (shipped -> live)
- Size 5796 -> 2705 (live is a SUBSET — boot-time comm, post-login comm grows it?).
- First bytes differ at offsets 11/19/27/35/42 (header/counters, not just payload).
- `config2/3.dat.<hash>`: content DIFFERS per install (device/session-bound — S-5
  device-bound candidate strengthened; same suffix `74c8e880` on two installs but
  different MD5 = suffix is schema/item id, content is per-device).

## Owned next (all offline)
1. TLV-variant framing resolve (live `comm.dat` full walk).
2. `tcj_encrypt` caller xref (find the record-name decryptor by code, not by cipher-guess).
3. `sig4/sig5` verification-key hunt (binary `__const` scan for 256 B modulus? Keychain item?).
