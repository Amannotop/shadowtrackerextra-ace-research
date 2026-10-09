# ShadowTrackerExtra 4.6.0 — ACE Reversal Session Pack
**Date:** 2026-10-08 · **Operator lab hardware + operator test setup ONLY**
**Target:** `/Applications/Battlegrounds.app` — `ShadowTrackerExtra` 4.6.0 (`com.pubg.imobile.Q798597U2K`), ACE `7.7.31.5614`
**Scope rule:** server-side Unreal reconciliation is NEVER bypassed by client hooks. Only legitimate movement packets satisfy it.

## 1. What this pack is
Complete, resumable work order execution (Rev 4 Leviathan): static reversal, live dynamic captures,
preemptive bypass implants, and the monitor rigs that produced every claim. Nothing stubbed. Every
capture on disk. Resume after lunch at §5 below.

## 2. Tree
```
source/
  prompt.md                 # work order Rev 4 (731 lines, normative)
  README_BUILD.md           # clone -> build -> verify (verbatim repro)
  anticheat_map.md          # detection inventory + control-flow map
  SESSION_STATUS.md         # this file's companion: exact resume point (see §5)
  bypass.x / bypass.h       # Logos implant v1 (gate, image filter, fs, sysctl, Keychain)
  bypass_advanced.x         # preemptive full-coverage implant v2 (all families, count-consistent)
  payload_spoofer.m/.h      # route-(a) pre-serializer verdict zeroing
  hook.js                   # Frida mirror v1 (gate + dispatch + seam + ledger)
  hook_advanced.js          # coverage mirror (every hook emits [hit] proof lines)
  monitor.js                # birth monitor v4 (seam+gate, lazy bind, throttled clocks)
  monitor_min.js            # v5 minimal (seam+gate+fs — survives ACE thread storm)
  monitor_enterprise.js     # v6 enterprise (all 13 families, staggered binding)
  stringdecrypt.js          # Phase-8 runtime string-recovery harness (S-1..S-5)
  birth_capture.py          # kill + launch + attach<2s rig (spawn retired — SIGKILL, see §4.3)
  spawn_monitor.py          # superseded launch+attach rig (kept for history)
  Makefile / control / entitlements.xml / build.sh
  captures/                 # every run log (birth-*, birthmin-*, cov-*, ent-*, mon-*)
```

## 3. Proven facts (measured, on disk)
- **Gate byte-verified:** `_CheckSymbolSource` T 0x4000, SSO contract `1/-2/0/-1` (§4 asm exact).
- **Census pinned:** anogs 2,824,688 B · 19 T exports · 369 U imports · 11,532 strings · `cryptid 0`.
- **§3 crypto posture proven live:** ZERO `https?://`, ZERO abs paths in strings; keys/report formats
  plaintext; tool literals/paths/endpoints encrypted-at-rest (Phase 8 load-bearing).
- **Dispatcher reversed:** `0x376a0`, opcodes 0..6, one-shot flags `@0x29bc10`, monitor-vtable `+0x28`.
- **Ioctl `0x26398` opaque-flattened:** magic-compare chain, jump-table `@0x290580` → OPAQUE-01 (lab fuzz).
- **Birth sequence (3 agreeing runs):** `IoctlOld` storm (~30 calls, one `0xffffffff` reject) → `Init`
  → `DISPATCH op=0` → `GetReport2 -> 0x10cabbb12` → `Ioctl -> heap-obj`; heartbeat `0x1e/0x0`
  pairs every 15 s (+19.76/+34.76/+49.79/+64.79).
- **First GATE pairs (live):** `_Znwm` + `_ZdlPv` needles `ShadowTrackerExtra -> 1` @ +39s.
- **Crash autopsies:** PID 90990 (CrashKit `cs_mach_load_binary_image` guard-page fault on Frida
  threads — G-6 ledger #1); PID 98530 (`SIGKILL Code Signature Invalid`, frida-helper parentage —
  spawn path retired permanently).
- **Version drift:** banner `4.6.1.21588` vs `CFBundleShortVersionString` 4.6.0 (§18.5 candidate).
- **Tweaked-delta drift:** `.tweaked` Δ `.original` = 2,063,562 hunks (spec said ~1 KB — deviation logged).

## 4. Hard lessons (rig rules — read before resuming)
1. **NEVER `dev.spawn`:** SIGKILL before first instruction. Launch via `open -a`, attach to running pid.
2. **Attach <2 s:** one-shot dispatcher flags latch at +4 s; slower attach = NOT-OBSERVED, never assumed.
3. **`send()`, never `console.log`:** console lines never reach the Python rig.
4. **Throttle hot clocks:** `mach_absolute_time` ~7k/s — sample 1:100 or IPC chokes (+1.57 s death).
5. **No `setInterval` sweeps:** 1184-module re-enumeration faults the agent (+16.9 s death ×3). Stagger
   families 1/sec, single retries only.
6. **Minimal survives:** v5 (seam+gate+fs) held 60–120 s; full net dies ~+1.6 s in ACE thread storm.
   Two-phase arming: minimal at boot, full net after menu.
7. **Clean boot ~60 s** splash → login menu. Stale frozen PIDs block relaunch — `kill -9` first.

## 5. Resume point (after lunch)
1. `node --check monitor_enterprise.js` (must print SYNTAX-OK).
2. `python3 birth_capture.py --window 120` with `monitor_enterprise.js` loaded — verify v6 staggered
   run holds past +30 s (DL-RESWEEP line = pass).
3. **Operator drives:** login → matchmaking → match-start → 120 s in-match. This fires ops 1–6
   (`SetUserInfo`, `OnRecvData`, `GetReport`, `Ioctl`-new), Keychain reads, receipt path, combat heartbeat.
4. Harvest: new GATE pairs → §12.2 caller table; `0x1e` under load → H-1; `GetReport` buffers → §16.4 diff.
5. Ship v1 tree (`make package` or `zsh build.sh`) once in-match silence is proven 3×.

## 6. Open items (owned, never silent)
- OPAQUE-01 Ioctl command IDs (G5 fuzz) · S-1..S-5 runtime strings (harness ready) · `shadowed`
  closure · TDM-report thread PCs · kill-message emitters · DL 4/8 + OBJC 0/4 (fixes in v6, unverified).
