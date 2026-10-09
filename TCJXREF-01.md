# TCJXREF-01.md — `tcj_encrypt` resolved: feature-flag oracle, NOT the cipher (KR, 2026-10-08)
**Method:** literal-pool xref + callee disassembly (`0xa231c`), zero accounts.

## Finding
- 2 call sites (`0x447f8`, `0x72e28`), identical shape:
  `x1="tcj_encrypt"|"HBCheck", w2=1, w3=1 → bl 0xa231c`, result byte `strb w0,[x19,#0x189]`.
- Callee `0xa231c(x0=ctx?, x1=name, w2, w3)`: tries cache/oracle `0xa23a0` first (fast path);
  on miss runs `0xa24e8 → 0xa2560` chain, `0x5a084` fallback; returns bool-ish (`cset w19,ne`).
- Sibling call passes `"HBCheck"` through the SAME oracle — this is the **feature-flag /
  capability-check dispatcher** (name → enabled?), not encryption. `tcj_encrypt` = "is TCJ
  crypto active for this session", result gates downstream branches (`eor w21,w21,#0x1` flip).
- Caller context (`0x447xx`): runs inside the ACE init path (post-`HBCheck` query, pre-`0xb3038`
  init with `w4=0x2800`): boot capability probe. Second site (`0x72e20`) = re-check
  (re-attestation? H-5 storm candidate — owned open item, cross-ref with background/foreground).

## Consequence
- The record-name cipher is NOT behind this symbol. The real decryptor lives behind the
  `comm.dat` reader path (TLV walk) — next xref: who reads `comm.dat`/`tss_ano.dat`
  (search `open`/`fopen` callers with those literals, or the `tlf` magic comparator).
- `0xa231c` itself is a NEW hook candidate (DET-G-08 capability-oracle): forcing
  `tcj_encrypt→0` may downgrade the whole crypto posture to plaintext. Lab-test only,
  menu-only run, journal-witnessed. Owner: next capture.
