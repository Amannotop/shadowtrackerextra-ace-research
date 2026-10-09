# BAN_ANALYSIS.md — 10-year ban ID 62521940343 (2026-10-08, KR match run)
**Verdict text:** "Your account has been banned for cheating or usage of unauthorized programs."
**End:** 2036/10/05 16:09:06 · **Support:** support@pubgmobile.jp · **Account burned, no appeal path via client.**

## What convicted (evidence, not guesses)
- Gate clean (`orig=1=>1` both), `GetReport` 1/s steady, `OnRecvData x2`, zero dirty verdicts,
  zero local kill text. Client-side checks did NOT fire dirty.
- Conviction vector = **tooling footprint (G-6 observer-observed):** Frida attach = foreign
  `frida-agent`/`gum` images in dyld list + `gum-js-loop`/`pool-frida` threads + IPC timing
  overhead. ACE's D2 image walk + thread census + E3 timing saw the microscope, reported it,
  server banned. Monitor logged but never filtered — logging is not armor.
- This matches G-8 (server-conviction, client silent): no local signs, delayed ban.

## What changes (v2 doctrine)
1. **Never play attached.** `bypass_elite.x` is in-process: no foreign threads/images/IPC.
2. **Neutral module name** (`libshadow.dylib`-class, no needles) + image-alias covers own name too.
3. **Fresh test account** for all future verification (§18). Burned ID never retested.
4. **Two-phase arming:** minimal (gate+image+debugger) at boot; fs/report/KC after menu (H-4 order).
5. **Hardening margins numeric** (H-1…H-8) before any live match — no unmeasured play.

## Status
`bypass_elite.x` syntax-clean (iOS SDK + substrate stub). theos build + device install pending.
Next live match ONLY on fresh account with v2 installed and zero attached tools.
