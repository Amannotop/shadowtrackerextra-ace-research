# ShadowTrackerExtra ACE — Reversal & Research Platform

Static + dynamic reversal of ACE (`anogs`) as shipped in ShadowTrackerExtra 4.6.0
(IMOBILE + KR rows), with a forensic framework, an in-process research implant,
and the full evidence trail. Operator lab hardware only.

> **Status:** client-side coverage complete (gate, seam, debugger, integrity,
> identity-story). Server-side lineage verdicts are documented, not defeated —
> see `BAN_ANALYSIS.md` and `SESSION_PACK.md` for the honest ledger.

## Layout

| Path | What |
|---|---|
| `libshadow.m` + `fishhook.[ch]` | Research implant (clang-only, universal arm64/arm64e). Spoofs debugger/JB/timing/image-list/identity signals, journals everything to `$TMPDIR/shadow_ace.log`. Build: `make`. |
| `shadow_log.py` | Journal viewer/aggregator. |
| `SentinelForge/` | Forensic framework: `analyze` (9 collectors → correlate → JSON+MD) + `diff` (ranked A-vs-B deltas). |
| `*-01.md`, `STATIC-CUTS*.md`, `STRSTATIC-KR.md` | Evidence docs (read in the order listed in `SESSION_PACK.md`). |
| `SESSION_PACK.md` | Full session handoff — targets, addresses, doctrine, open queue. |
| `BAN_ANALYSIS.md` | Ban autopsies + tooling-footprint verdicts. |
| `MULTI_VERSION.md` | Fingerprint table for both version rows. |
| `birth_capture.py`, `banwatch.js`, `monitor_enterprise.js`, `xmlgrab.js`, `parsegrab2.js`, `cmpgrab.js`, `stagewatch.js`, `stringdecrypt.js` | Monitors & rigs (Frida-based, menu-only doctrine). |
| `version_manager.h`, `version_probe.py` | Multi-version support. |
| `archive/superseded-v1/` | Retired first-gen files. |
| `captures/` | Local-only run journals (git-ignored). |

## Quick start

```bash
make                    # builds libshadow.dylib (Xcode CLT, iOS SDK)
make test-log           # tail the journal viewer
cd SentinelForge && make
```

Live run (menu-only, no login — see doctrine):

```bash
open --env DYLD_INSERT_LIBRARIES=$PWD/libshadow.dylib -a "PUBG MOBILE"
python3 shadow_log.py --all
```

## Doctrine

1. Never `dev.spawn` (SIGKILL). Attach or `DYLD_INSERT_LIBRARIES` only.
2. Menu-only runs. Fresh identity per live test. No attached play.
3. Operator tooling is out of scope — never touch, filter, or suspect it.
4. Static-first: disasm/census/menu-capture need no account.

## License

MIT — research and education.
