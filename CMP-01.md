# CMP-01.md — comparator mapped, full manifest table (KR menu-only, PID 70083, 2026-10-08)
**Log:** `captures/cmp-*/cmp.log`. **Target:** `0x17470` = generic byte comparator
(strncmp-class: walks both pointers, returns first-diff or 0; a2/a3 = bounds/flags).

## Full verify manifest (from B-sides, in order)
`sig5 | comm_custom.zip | comm.zip | comm_ver.zip | tlf | req_custom | gs_lo | sav_req |
wr:%d | dl:%s,stat:%d | gs_it | disable_cs | …`
(+ `tss_ano.dat` compared against `comm.zip` → diff at index 17, `ret=0x11` — member
selection by name-match, NOT content-compare here.)
- `comm_custom.zip` is NEW (custom-overrides archive — triage: does it exist on disk?).
- `disable_cs` + `gs_it` are NEW literals (config keys? feature flags? — grep + xref next).
- `dl:%s,stat:%d` + `wr:%d` = the DoRisk/dl-stat format pair live in the manifest context.

## Key-hunt verdict (parked, not dropped)
- 3 runs, 2 statics, 1 ABI reversal: verify = in-house SHA-256 + memcmp against `sig4/sig5`
  contents; expected-value encoding (salt/mask/key) still opaque; RSA-shape absent from
  `__text` (no modexp — 256 B sigs likely hold salted digests + metadata, verified by
  recomputation with an internal salt, NOT asymmetric crypto).
- Diminishing returns: route-(a) (pre-serializer zeroing, authentic signing preserved) NEVER
  needed the key. Key hunt PARKED at SIGKEY-01/SIGVERIFY-02 state; re-open ONLY if route-(a)
  fails a live diff. Next efficient step if reopened: capture `0xcbfe8`'s salt input
  (the extra buffer beyond the member bytes), not the key.
