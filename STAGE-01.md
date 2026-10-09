# STAGE-01.md — report workspace on disk (KR container, menu-only run, 2026-10-08)
**Path:** `<container>/Data/Documents/ano_tmp/` (3 containers, one per install).
**Method:** direct read, zero accounts. Timestamps 16:55–17:15 = today's runs.

## Inventory (`ano_tmp/`, KR container A842799E)
| File | Size | Mtime | Read |
|---|---|---|---|
| `ac_tmp/` | dir | 16:55 | list next |
| `ano_app_915c.dat` | 24 B | 16:55 | random blob (key/token?) |
| `ano_uts_c2.dat` | 32 B | 17:15 | structured: `21 06 18 20 1e00…` + 16 B payload `425e5d47…` |
| `comm.dat` | 2705 B | 17:15 | `tlf` magic + TLV records (below) |
| `comm.zip` | 4056 B | 16:55 | zipped comm (compare!) |
| `config2.dat.8e444d80` | 3158 B | 17:15 | hash-suffixed config (server-issued? S-5 candidate) |
| `config3.dat.b3246430` | 3962 B | 17:15 | same family |
| `fake_uiui.dat` | 31 B | 16:56 | obfuscated ascii (`uqu`, `stq|vwq` — Caesar/rot variant? decode next) |
| `kvcache8.dat` | 60 B | 16:55 | KV records (`]T_l@TS…QT…WmAQ…`) |
| `mrpcs-cs-6139-ios.data` | 26836 B | 16:55 | RPC payload (matches `CParseMRpcsComData`!) |
| `mrpcsZ_cp.data` | 82248 B | 16:55 | compressed RPC twin (`Z` = zlib? `inflate` import says yes) |
| `p_tlc6.d` | 4 B | 16:55 | `12P.` (counter/marker?) |

## `comm.dat` structure (TLV, little-endian)
- Magic `00 00 00 03 'tlf' 00`, then records: `[tag:u16][len:u16][payload…]`
  (`000c 0000 2100…`, `006b 0000 0700…`, `00bf 0000 0800…` — tag/len pairs walk cleanly).
- Next: full TLV walk (script `tlvwalk.py`), tag→meaning via cross-ref with §8 formats
  (`a:%d,r:%d` = tag? `check_state` = tag? `inc_id` = tag?).

## Findings vs prior claims
- Staging files are BINARY TLV, not XML text — TinyXML (`LinkEndChild`) likely builds the
  *transport envelope*, TLV structs are the *payload*. §16 schema = envelope + TLV map.
- `config2/3.dat.<hash>` = server-issued content (hash suffix = version/etag) — S-5
  server-issued candidate strengthened; diff across runs to confirm rotation.
- `fake_uiui.dat` name + weak obfuscation = device-ID-adjacent? Decode next (rotasc sweep).
- `tss_ano.dat` / `/tmp.xx.dat` ABSENT at menu (created post-login or post-match — owned open item).
