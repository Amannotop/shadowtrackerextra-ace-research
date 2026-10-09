# PARSE-01.md — sig-verify manifest + parse capture (KR menu-only, PID 68928, 2026-10-08)
**Log:** `captures/parse-20261008-*/parse.log`.

## Sig-verify (`0x502b4`) — PASS (`-> 0x0`), manifest recovered
- `x1` = `"PK\x03\x04"` (ZIP local-file header — verifies the ZIP, not loose files).
- `x0` manifest = `comm.zip | comm_ver.zip | tlf | req_custom | gs_lo | sav_req` (+ formats
  `wr:%d`, `dl:%s,s…`): the verify SET = 6 named members. `sig5` is the signature name
  (x3/x4 pair per COMMREAD-01: `comm.dat` + `sig5`).
- `0x17470` is a byte-stepping comparator (`comm.dat` → `omm.dat` → … → ``, same for
  `sig5`, `tlf`): memcmp-style loop, NOT a hash. Comparison target unknown (plaintext?
  decrypted candidate?) — capture its OTHER operand next (a0/a2).
- `0xeed68` fires ~10× in the same second (parse fan-out over members): inputs are
  per-member object addrs, outputs heap buffers (`0x9d…`). Input hex shows embedded
  ascii path `/Users/amansharma/Librar…` (container path inside a parsed struct!).

## Standing
- Verify-then-parse order confirmed live; manifest = 6 members; sig PASS on clean boot.
- Route-(b) needs: WHICH key verifies `sig5` (next: capture `0x502b4`'s key operand —
  its x2 was unreadable this run, retry with wider read) + full `0xeed68` output structs.
- `comm_ver.zip` is NEW (version manifest — diff vs `comm.zip` next).
