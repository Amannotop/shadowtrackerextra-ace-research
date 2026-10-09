# TRIAGE-01.md — `disable_cs` + `comm_custom.zip` (KR, 2026-10-08)
- `disable_cs` neighborhood (strings 10816–10819): `gs_it | disable_cs | cs_dl_5 | config2.xml`,
  right after `wr:%d | dl:%s,stat:%d`. `cs` = CrashSight/CrashKit (reporter control cluster:
  download slot 5? disable flag? `gs_it` = get-setting?). Reading: downloader/config channel
  for the crash reporter with a server-side kill-switch. Hook surface (DET-H-07 reporter
  channel): log `cs_dl_5`/`config2.xml` fetches on next menu-only run; server-driven content =
  Phase-3 capture item (lab proxy, no account).
- `config2.xml` = CONFIRMS the XML envelope (matches TinyXML `LinkEndChild`).
- `comm_custom.zip` ABSENT on disk (all containers + X-dirs) = server-issued post-login
  (or post-match). Cannot be triaged menu-only — owned open item for the login run
  (fresh identity only, per ban doctrine).
