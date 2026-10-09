# MULTI_VERSION.md — update workflow (enterprise-grade, zero silent substitution)

## Rule
A new game version NEVER reuses an old row. Probe → verify → append → re-capture → ship.
Unknown fingerprint at load = safe-disable + log. Blind-hooking an unknown build is a defect.

## When the game updates (operator checklist)
1. **Probe:** `python3 version_probe.py --app <new Bundle.app path>` → fresh row values
   (version, anogs sha256, T/U counts, seam offsets, gate byte-check).
2. **Diff vs last row:** T-count change = export surface moved (new seam members?).
   U-count change = new imports (new detection family?). String-count swing >5% = crypto
   posture shift (re-run §3 census: URL/path/tool sweeps must still read ZERO/static).
3. **Gate re-verify:** first-4-insns MUST match §4 (`sub sp / stp x20,x19 / stp x29,x30 /
   add x29`). Mismatch = gate rewritten → HOOK-D-01 needs redesign, not re-offset.
4. **Dispatcher re-map:** disassemble new `0x376a0`-equivalent (find via `Init` export + `bl`
   follower): opcode ceiling still 6? flag-table layout same? Record new offsets.
5. **Append row** to `kVersions[]` in `version_manager.h`. NEVER edit the old row.
6. **Re-capture:** `birth_capture.py` + enterprise monitor on the new build, idle baseline +
   in-match run. New GATE pairs, new heartbeat cadence, new `0xffffffff`-class rejects.
7. **Ship:** `make package` emits one artifact covering all rows; loader picks row by
   fingerprint at `%ctor` time and reports per-hook ARMED/UNSUPPORTED/FAILED.

## Current table
- `4.6.0` (`com.pubg.imobile.Q798597U2K`) — sha `5c8dae8b…08508d49`, T=19, U=369,
  strings=11,532. Baseline (this session).
- `4.6.0-kr` (`com.pubg.krmobile.Q798597U2K`, `/Applications/PUBG MOBILE.app`) —
  sha `3186d4f3…bde064db`, T=19, U=369, strings=11,532. Seam offsets + gate bytes
  IDENTICAL to baseline (same ACE, region content delta in main: 183MB vs 164MB).
  Same hook table, separate fingerprint row. Birth-capture on KR pending.
- `4.6.1.21588` (banner string; bundle still 4.6.0) — PENDING probe: confirm whether anogs
  bytes differ from the 4.6.0 row or this is display-only drift.

- OPERATOR TOOLING (out-of-scope, never analyzed, never hooked): `reset guest.dylib`
  (guest-data reset aid) and any operator-side helpers. ACE enumerates them as images;
  that is expected and accepted — do not touch, do not suspect, do not filter.
