# README_BUILD.md — Clone → Build → Verify (verbatim, zero-question repro)

## 0. Scope
Operator-owned lab hardware + operator-owned test device ONLY. Target: ShadowTrackerExtra 4.6.0
(`com.pubg.imobile.Q798597U2K`). Server-side Unreal reconciliation is NEVER bypassed by client hooks —
only legitimate movement packets satisfy it.

## 1. Clone + layout
```
source/
  bypass.x  bypass.h  payload_spoofer.m  payload_spoofer.h
  hook.js  stringdecrypt.js
  Makefile  control  entitlements.xml  build.sh
  README_BUILD.md  anticheat_map.md  test_log.md  strdump.md
  captures/
```

## 2. Toolchain (App. H pins — record actuals)
- macOS 26.4.1 (25E253), Xcode 26.6 (17F113), Python 3.9.6
- Frida 17.22.2, frida-tools 14.11.0 (`/Users/amansharma/Library/Python/3.9/bin`)
- theos (latest) for `make`; else `zsh build.sh` (exact clang flags)

## 3. Build (theos)
```
export PATH="$PATH:/Users/amansharma/Library/Python/3.9/bin"
make package
```
Expected: `ShadowBypass` .deb emitted, zero warnings beyond `-Wno-unused-parameter`.
Fallback: `zsh build.sh` → `bypass.dylib` + ad-hoc sign. Expected: `[build] signed OK`.

## 4. Lab install (rootless + rootful)
- Copy .deb to lab device, install via Sileo/Zebra (rootless scheme) or dpkg (rootful).
- Respring / re-launch `com.pubg.imobile.Q798597U2K`.
- Verify ctor order: dispatch-op log must show hooks armed BEFORE first `AnoSDKInit` op.

## 5. Frida mirror (lab dynamic)
```
frida -n "Battlegrounds" -l hook.js -q
# drive: launch -> login -> matchmaking -> match-start -> 120s in-match
```
Expected: `[hook] all hooks armed`, gate lines `gate(sym , needle) -> N => 1`, no kill text, no crash.

## 6. String recovery (Phase 8)
```
frida -n "Battlegrounds" -l stringdecrypt.js -q
# at each lifecycle point, in REPL: strdump()
```
Expected: S-1/S-2/S-3 sets grow across lifecycle; deltas vs static recorded in `strdump.md`.

## 7. Verify
- `test_log.md` matrix: per-ID SILENCED / TRIPWIRE-fixed / OPEN (blocker-filled, never blank).
- 3× ≥120 s in-match sessions, capture files per session, honest post-window recorded.
- `§16.4` forged-vs-genuine-clean diff byte-exact (freshness fields excluded, displayed).

## 8. Failure routing (Appendix G)
Crash ≤3 s same site → G-1 (keep hook, ascend ONE caller). Clean UI + dirty keys in capture → G-2.
Bans with clean payloads → G-3 (heartbeat-absence). Any Frida/thread in image hits → G-6 ledger.
