# STRSTATIC-KR.md — Phase-8 static string-recovery record, KR 4.6.0 (`4.6.0-kr` row)
**Date:** 2026-10-08 · **Method:** offline `strings` census + disassembly, zero accounts, zero logins.
**Binary:** anogs KR sha `3186d4f3…bde064db` · 11,532 strings · T=19 · U=369.

## S-1 endpoints/URLs — STATIC: EMPTY (confirmed encrypted-at-rest)
- `https?://`: 0 hits. Absolute `/var/ /private/ /Applications/` literals: 0 hits.
- Host/port/path fragments (`:80`, `.com/`, `/tdm`, `/report`, `/verify`, `/attest`, `/sdk`, `/api`,
  `heartbeat`): 0 genuine hits (only FP noise + ObjC type encodings `@24@0:8:16`).
- **Inference (evidence-backed):** endpoints materialize at runtime (decrypt-on-use) or piecewise
  via the §8 `%s/%d/%p/%x` format grammar. Static S-1 = UNDER-SPECIFIED by construction (§3.2).
- **Runtime plan (no account needed):** `stringdecrypt.js` S-1 (`connect`/`dataTask` arg capture +
  post-`Init` heap grep) on a **menu-only, no-login** run. Login is NOT required for endpoint
  materialization (heartbeat + attest fire pre-login per birth captures).

## S-2 probed paths — STATIC: EMPTY (confirmed encrypted-at-rest)
- JB/tool path literals (`Cydia`, `Substrate`, `frida`, `jailbreak`, `.dylib`, `.plist`,
  `mobileprovision`): 0 hits. Only garbage fragments (`/4)j`, `/5))` — FP).
- Live FS journal corroborates: only `/Applications/Cydia.app` +
  `/Library/MobileSubstrate/MobileSubstrate.dylib` observed at runtime (2 probes, both denied).
- **Runtime plan:** S-2 hook-dump vs decrypt-dump reconciliation (§20-S-2) on menu-only run.
  Any delta = logger-bypass probes (highest interest).

## S-3 gate pairs — STATIC: EMPTY (confirmed piecewise/encrypted)
- `CheckSymbolSource`/`CheckNewDylib`: 0 hits in BOTH binaries (main + anogs).
- Live pairs known: `(_Znwm, ShadowTrackerExtra)`, `(_ZdlPv, ShadowTrackerExtra)` — 2/2 clean.
- **Runtime plan:** gate-pair logger (already in `hook_advanced.js`) on menu-only run; full pair
  table = §12.2 caller table. No login needed (gate fires +39 s at menu).

## S-4 tool literals — STATIC: ONE (`shadowed`)
- Sweep (`frida|gum|substrate|substitute|cydia|sileo|zebra|choicy|hestia|libhooker|dopamine|
  bootstrap|trollstore|unc0ver|taurine|odyssey|checkra1n|shadow`): single hit `shadowed`
  (neighbors: `%s %s %s %s %d %d` / `%s,%s` / `inc_id:%d` — verdict-format context, §8 family).
- `shadowed` resolution: OPEN, single owner, Phase-1 F4 row.
- **Runtime plan:** post-decrypt heap grep for the full tool list (§20-S-4); each hit → F-row,
  each miss → `NEG-` with full pedigree (§3.5: static + runtime dump + memory grep + window).

## S-5 transform hunt — CANDIDATES (static evidence each)
1. **XOR/rolling const near `__const`** — OPEN (needs disasm pass over decryptor-callers).
2. **`libz` compressed tables** — OPEN (`inflate` import present? verify in U-list; `tcj_encrypt`
   + `!tcj,name:%s md5:%s,size:%d` suggest hashed manifest, not string crypto).
3. **`mmap`'d blobs** — OPEN (`mmap` imported; packed-blob mapping per §5).
4. **Device-bound (CFUUID keystream)** — OPEN (`CFUUIDCreate*` imported; test = compare two
   installs' runtime strings).
5. **Server-issued via `OnRecvData`** — OPEN (`OnRecvData x2` observed live; test = diff
   pre/post-`OnRecvData` memory on menu-only run — NO login needed, server pushes pre-login).
- **Build-leak bonus:** `/Users/tpbuilder/tpmobile/workspace/p-43930cd7b…/sdk-private/source/common/xml/
  tinyxml*.cpp` — build user `tpbuilder`, workspace hash, **report serializer = TinyXML
  (XML reports, NOT JSON — §16.1 schema must be XML)**. `CParseMRpcsComData` = RPC parser class.

## Transport confirmation (KR = baseline)
- `_AnoSDKIoctl -> 0x26398`, all 19 seam offsets identical, gate bytes identical. Same ACE core.
- Next static steps: dispatcher `0x376a0` opcode-table re-verify on KR (expect same 0..6);
  `0x26398` magic-chain diff vs baseline (expect identical); TinyXML report-field extraction
  via `ChkInit/SetUserInfoEx` format refs (already harvested: entry_id/uin/app_id/world_id/role_id).
