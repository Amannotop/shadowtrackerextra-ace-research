# STATIC-CUTS3.md — XML element map attempt (KR, 2026-10-08)
**Method:** `GetReportData 0x1a25c` callee walk + tag/API string sweep, zero accounts.

## Result: STATIC ELEMENT MAP BLOCKED (evidence-backed, not a skip)
- `0x1a25c` = vtable dispatch (`ldr x1,[x8,#0xb0]; br x1`) into flattened magic-chains
  (`0xd8bae917 / 0x32a7d5cf / 0x1c4ed7a6` family) — same obfuscation class as Ioctl.
- Tag sweep (`<[A-Za-z/]`, `encoding`, `SetAttribute`, `XMLElement`, …): ZERO plaintext element
  names. Sole TinyXML witnesses: `LinkEndChild`, `~TiXmlAttributeSet`, `CParseMRpcsComData`,
  `TIXML_ERROR_STRING_COUNT`, build paths. Element/attribute NAMES are encrypted-at-rest
  (same §3 class as endpoints/paths).
- Filed as `NEG-STATIC-XMLMAP` with pedigree: 11,532-string sweep + callee-walk `0x1a25c →
  0x6996c/0x35b30/0x35644` + API-name sweep. Static-only report reconstruction is
  REJECTED as under-specified (§10.2-9) — same rule as paths/endpoints.

## Runtime plan (menu-only, no account, no login)
- `stringdecrypt.js` S-block + `GetReportData*` buffer capture on a **menu-only run**:
  buffers contain the BUILT XML (post-decrypt, pre-transmit) — element/attribute names read
  straight off the heap. No login needed (GetReport2 fires at boot, proven 3 runs).
- Reconcile vs `LinkEndChild` call-sites (caller addrs from disasm) → per-element producer map.
- Owner: next menu-only capture session. Blocker if any: none known — buffers already
  observed (`GetReport2 -> 0x10cabbb12` class pointers, 3 runs).
