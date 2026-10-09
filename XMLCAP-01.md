# XMLCAP-01.md — menu-only report-buffer capture (KR, 2026-10-08, PID 66028)
**Method:** Frida buffer read on `GetReportData*` returns, menu-only (no login, no account touched).
**Log:** `captures/xml-20261008-170950/xml.log` (31 lines).

## Buffer (GetReport2 -> 0x10c6a7b12, +3.5 s post-launch, 4 KB probe)
Plaintext artifacts in the live report workspace:
- `sem_%d_%d` — semaphore/named-sync template (report-sync primitive?)
- `vm_main.img` / `vm_x_task.img` / `vm_debug.img` — VM/integrity image set (self-hash inputs, ×D5/A7)
- `ano_tmp` / `tss_ano.dat` / `/tmp.xx.dat` — report staging files (workspace paths!)
- `tersafe.update` — updater channel marker

## Static-vs-runtime delta (finding per §20 rule)
- Static (11,532 strings): `vm_main.img` ✓, `vm_x_task.img` ✓, `tmp.xx.dat` ✓.
- Runtime-only: `vm_debug.img` ✗, `ano_tmp` ✗, `tss_ano.dat` ✗, `tersafe.update` ✗, `sem_%d_%d` ✗.
- 5/8 artifacts are runtime-materialized — decrypt-on-use confirmed for workspace paths.
  A path-filter built from static strings alone misses the majority of the workspace.

## Notes
- Single `GetReport2` in 100 s menu-idle (report pipeline quiet pre-login; serializer alive).
- `GetReport/3/4` silent at menu (login-gated, expected — ops 1–6 wait on drive).
- Staging files (`tss_ano.dat`, `/tmp.xx.dat`) = new triage targets (Phase-0 artifact class):
  read pre/post-match on next menu-only run; content = serialized verdicts in the clear?
