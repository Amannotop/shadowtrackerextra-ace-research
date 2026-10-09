# anticheat_map.md — Inventory + control-flow map (ShadowTrackerExtra 4.6.0, anogs 7.7.31.5614)

## Detected IDs (Phase 1 Batch 1 — extend, never redo)
- DET-G-01 [P0]: central dispatcher 0x376a0, opcodes 0..6, one-shot flags @0x29bc10, monitor-vtable +0x28
- DET-G-02 [P0]: 19-export opcode map (Init/SetUserInfo/Pause/Resume/GetReport/DelReport/OnRecvData/Ioctl/IoctlOld/Free/Get2-4/Del3-4/RecvSig/RegistListener)
- DET-G-03 [P0]: Ioctl obfuscated dispatch 0x26398 — OPAQUE-01, lab fuzz 0..N required
- DET-I-01 [P1]: identity bind struct (entry_id/uin/app_id/world_id/role_id) → cheat_open_id / s_open_id
- DET-D-01 [P0]: _CheckSymbolSource gate (1/-2/0/-1 contract, SSO §4.1) → HOOK-D-01 neuter→1
- DET-D-02 [P0]: image-count/name loop → count-consistent filter (alias, never remove)
- DET-E-01 [P0]: sysctl P_TRACED → flag-clear spoof
- DET-B-01..07 [P0]: sideload markers (sideloadly.tag/.jbroot/.original/.tweaked/.prelib/.rebuild) → path-EXACT spoof
- DET-C-01 [P0]: JB path probes → same fs hooks (S-2 runtime set extends static seed)
- DET-J-06 [P0]: thread map — ace_schedule3 (+545968) / ace_worker0 (+560760) / 5 anogs sleepers / TDM-report-1 / TDM-Timer-2
- DET-A-03 [P1]: appStoreReceiptURL → AdjustSigSdk sign path (live thread-68 chain)

## Control flow (gate lit)
```
checks (gate D-01 → fs/sysctl/dlopen/opcode/timing probes)
  → verdicts (a:%d,r:%d / check_state / debugger flags)
    → GetReportData* (0xf10dc/74/78/80) → serializer → transmitter → endpoint (S-1 set)
      → server action (ban/kick/shadowban) | local-kill (_exit/_kill)
challenge path: OnRecvData/OnRecvSignature → tcj_encrypt → wait_token_resp → cs_host
heartbeat: HBCheck / force_hb / DisconnHBCnt / disconn_cs_no_heart → c2g_rediect / ace_cs2/3
```

## Open items (owner-phased, never silent)
- OPAQUE-01: Ioctl command IDs (Phase 1-G5 fuzz)
- S-1..S-5: runtime string sets (Phase 8 harness shipped)
- NEG-shadows: `shadowed` closure row (single-owner NEG- or meaning)
- TDM PCs + kill emitters (Phase 1 Batch 2)
