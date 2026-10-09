# SESSION PACK — ShadowTrackerExtra ACE Reversal (2026-10-07 → 2026-10-09)
**Scope:** operator-owned lab hardware + operator test setup ONLY. Server-side Unreal
reconciliation NEVER bypassed by client hooks. 3 test accounts burned (10-y bans) during
Frida-attached live play — full doctrine change filed (no attached play, ever).

## 1. Targets (2 version rows, verified — not assumed)
| Row | Bundle | ID | anogs SHA256 | T/U/strings | Main |
|---|---|---|---|---|---|
| `4.6.0` | `/Applications/Battlegrounds.app` | `com.pubg.imobile.Q798597U2K` | `5c8dae8b…08508d49` | 19/369/11,532 | 164 MB |
| `4.6.0-kr` | `/Applications/PUBG MOBILE.app` | `com.pubg.krmobile.Q798597U2K` | `3186d4f3…bde064db` | 19/369/11,532 | 183 MB |
- Same ACE core by byte-proof: gate bytes, 19 seam offsets, dispatcher `0x376a0`,
  Ioctl `0x26398` magics — ALL identical across rows. Main differs = region content.
- KR extras: CrashSight suite (renamed CrashKit), MSDK/curl/PixUI stacks, `MeemoApp`,
  `flutter_qapm`, bundled `CydiaSubstrate.framework` (ACE's own — NEVER filter),
  operator tool `reset guest.dylib` (OUT OF SCOPE, never touched).
- Provisioning (both): Xcode-managed dev, same team `Q798597U2K`, 7-day expiry,
  `get-task-allow=true`. Sideload markers: `sideloadly.tag/.jbroot/.original/.tweaked/.prelib/.rebuild`.

## 2. Reversed core (measured, on disk)
- **Gate `_CheckSymbolSource`** T 0x4000, contract `1/-2/0/-1`, SSO `+0x17` (§4 bytes exact).
  Live pairs: `(_Znwm, ShadowTrackerExtra)`, `(_ZdlPv, ShadowTrackerExtra)` → all `1`.
- **Dispatcher `0x376a0`:** opcodes 0–6, one-shot flags `@0x29bc10`, monitor-vtable `+0x28`.
- **Boot sequence:** `IoctlOld` storm (~30, one `0xffffffff` reject) → `Init` → `DISPATCH op=0`
  → `GetReport2` → `Ioctl`. Heartbeat `0x1e/0x0` every 15 s. `SetUserInfo` + `OnRecvData x2`
  at login; `GetReport` 1/s in match.
- **Crypto posture (§3 proven):** 0 URLs, 0 abs paths, 0 tool literals (except `shadowed`)
  in 11,532 strings — endpoints/paths/needles encrypted-at-rest, Phase 8 load-bearing.
- **Report = XML (TinyXML `LinkEndChild`) + TLV payloads** (`tlf` magic; `CParseMRpcsComData`).
- **comm chain:** boot bitmask `0x4e24` (DET-G-09) → verify `0xa34f0` (`sig5` + member +
  `0x502b4`) → parse `0xeed68/70` → staging `ano_tmp/` (comm.dat/comm.zip/sig4/sig5,
  configs, mrpcs twins, KV cache). Manifest: `sig5|comm_custom.zip|comm.zip|comm_ver.zip|
  tlf|req_custom|gs_lo|sav_req|wr:%d|dl:%s,stat:%d|gs_it|disable_cs|…`.
- **Sig-verify = in-house SHA-256** (`0xcb5e4` compression) + memcmp (`0x17470`); NO RSA
  (no modexp in `__text`, no crypto imports); expected-value encoding salted/masked —
  key hunt PARKED (route-(a) needs no key).
- **`tcj_encrypt` = capability oracle** (`0xa231c`, shared with `HBCheck`), not the cipher —
  DET-G-08 (force-0 downgrade candidate).
- **ACE threads:** `ace_schedule3`/`ace_worker0`/sleepers + `TDM-report*` + `mgpa_handler`.

## 3. Implants + monitors (source/)
- `libshadow.dylib` (universal arm64/arm64e, ~167 KB, clang-only, fishhook, zero deps):
  gate neuter, narrow image-alias (basename+scope guards — game/Apple exempt), fs path-EXACT
  (28 markers), sysctl/ptrace/syscall debugger spoofs, 1 ms timing clamp, thread-name
  sanitizer, report-hash logging, Keychain tripwire, local-kill tripwire, NET witness,
  v4.1 JSON journal (`dt/epoch/sess/up_ms/n/fam/ev/d`) + `shadow_log.py` viewer.
  LESSONS: no `__DATA,__interpose` (dyld-init NULL-orig crashes ×2), `dprintf` not write-loop,
  guard `orig==NULL` in every hook (abs-during-init crash).
- `bypass_elite.x` (theos/substrate path, dual Makefile target `libshadow` neutral name).
- Monitors: `banwatch.js` (18-seam + verdicts + kill-proof), `monitor_enterprise.js` (13
  families, staggered binding), `xmlgrab.js`, `parsegrab2.js`, `cmpgrab.js`, `stagewatch.js`.
- Rigs: `birth_capture.py` (kill+launch+attach<2 s), `watchdog`/`elite`/`cov`/`ent` variants.
- 23 capture dirs in `captures/` (birth/birthmin/cov/ent/mon/xml/stage/parse/cmp/banwatch/watch/elite).

## 4. Docs (source/*.md — read in this order on resume)
1. `SESSION_STATUS.md` (original handoff) 2. `BAN_ANALYSIS.md` (10-y ban #1, tooling-footprint
   verdict) 3. `MULTI_VERSION.md` (+ operator-tooling exemption) 4. `STRSTATIC-KR.md` (S-1..S-5)
   5. `STATIC-CUTS2.md` (dispatcher/Ioctl/XML) 6. `STATIC-CUTS3.md` (NEG-STATIC-XMLMAP)
   7. `XMLCAP-01.md` (report workspace buffer) 8. `STAGE-01.md` (ano_tmp inventory)
   9. `COMM-01.md` (shipped-vs-live) 10. `COMMREAD-01.md` (load/verify/parse chain)
   11. `TCJXREF-01.md` (flag oracle) 12. `PARSE-01/02.md` (manifest + ABI)
   13. `SIGVERIFY-01/02.md`, `SIGKEY-01.md` (hash-compare, key parked) 14. `CMP-01.md`
   (comparator + full manifest) 15. `TRIAGE-01.md` (disable_cs, comm_custom)
   16. `README_BUILD.md`, `anticheat_map.md`.

## 5. SentinelForge/ (new platform — IN PROGRESS, builds with warnings)
Forensic framework: `analyze` (9 collectors → iterate → correlate → JSON+MD) + `diff`
(A-vs-B ranked deltas). Status: compiles to `sentinelforge` binary BUT `make` needs a
clean rebuild (stdio fix applied, struct-redef fix applied — verify with `make clean && make`).
Remaining: tests/ (`run_tests.sh` missing), docs/, config/, README, ObjC/Swift metadata
module, branch-proximity stage, fat-slice `symoff` validation. See build errors in session log.

## 6. Doctrine (non-negotiable)
1. NEVER `dev.spawn` (SIGKILL). NEVER play Frida-attached (3/3 bans). Menu-only ≤100 s runs.
2. No play until GATE lines proven in journal at menu. Fresh identity per live test.
3. Operator tooling (`reset guest.dylib`) out of scope, forever.
4. Static-first: no account needed for disasm/census/capture-at-menu.
5. Server bans are irreversible client-side; burned IDs stay burned.

## 7. Open queue (ranked)
1. SentinelForge: `make clean && make`, write `tests/run_tests.sh`, docs/, config/, README.
2. `0xeed68` output structs (parsed-record layout — cipher dies here).
3. `disable_cs`/`cs_dl_5` channel log (DET-H-07) + `config2.xml` fetch capture.
4. `0x4e24` init-bitmask transcript (clean-boot baseline).
5. `comm_custom.zip` server-issued capture (fresh identity only).
6. Store-spoof assessment (honest split: bundle-id/team-id spoofable client-side;
   receipt/AppAttest/provision/server checks NOT — doc CAN-vs-CANNOT matrix).
