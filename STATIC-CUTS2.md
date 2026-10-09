# STATIC-CUTS2.md — dispatcher + Ioctl + XML schema (KR vs baseline, 2026-10-08)
**Method:** offline disassembly diff, zero accounts.

## 1. Dispatcher `0x376a0` — BYTE-IDENTICAL (KR = baseline)
- Prologue, `bl 0x370d0`, `cmp w20,#0x6`, flag table `@0x29bc10`, jump-table `@0x23c6d0`,
  first handler code `0x8392 -> 0xfe434`: all identical instruction-for-instruction.
- Opcode ceiling 6, one-shot flags, monitor-vtable chain: shared. `kVersions` opcode fields hold.

## 2. Ioctl `0x26398` magic chain — IDENTICAL (first 16 magics)
- Seed `0x31c04ca0`, comparators `0xea92b28e / 0xabde417a / 0x5ab27782 / 0x1a2241fe`,
  indices `0x160/0x13c`, follow-ups `0x11a1060f…`: identical.
- OPAQUE-01 is ONE opaque surface across both variants — a single lab fuzz covers both rows.

## 3. Report schema is XML (TinyXML) — field map v1
Identity/binding fields (from `SetUserInfoEx` + report formats):
- `user_info->{size_, entry_id_, uin_{type,int,str}, app_id_{type,int,str}, world_id_, role_id_}`
- Report keys: `cheat_open_id`, `s_open_id` (triple-format: bare / `:%s` / `=%s`),
  `%s;role_id:%s;inc_id:%d;obf_id:%d`, `role_id:%s;inc_id:%d`
- Bundle fields: `CFBundleShortVersionString/Version/DisplayName`, `bundleIdentifier`,
  `mainBundle/bundlePath`, `appStoreReceiptURL`, `attestKey:clientDataHash:completionHandler:`
- Verdict/state: `a:%d,r:%d`, `a:1,r:%d,cnt:%zd`, `check_state`, `debugger` families (§8)
- **Correction filed:** §16.1 JSON sketch is SUPERSEDED — serializer is TinyXML
  (`CParseMRpcsComData`, `TIXML_ERROR_STRING_COUNT`). Forged-transmitter work must target
  XML element/attribute order, not JSON keys. Full element map = next static cut
  (string-ref walk from `GetReportData2 0x24dc0` + `GetReportData 0x1a25c` callees).

## Standing
Both version rows share one ACE core by proof, not assumption: gate bytes, seam offsets,
dispatcher, Ioctl magics identical. The multi-version table is verified, not just filled.
