# SIGVERIFY-02.md — hash confirmed SHA-256 in-house; expected-value still opaque (KR, 2026-10-08)
- `0xcb5e4` = SHA-256 compression (Ch/Maj + ror + K schedule). In-house, no imports.
- Member digests (SHA-256/512/MD5/SHA-1 over shipped `comm.dat`/`sig4`/`sig5`) all ABSENT
  from `sig5` → expected values are salted/masked/keyed, OR `sig5` holds a different member set.
- EFFICIENT next (menu-only, owned): hook comparator `0x17470`, log BOTH operands —
  computed-digest vs expected-bytes side-by-side. One run closes the encoding question.
  (Current `tlfcheck` hook only logged one side stepping — extend to dump both buffers + lengths.)
