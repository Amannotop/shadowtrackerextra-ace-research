#!/usr/bin/env python3
# shadow_log.py — read + summarize shadow_ace.log v4 (human datetime + session + uptime)
"""Usage: python3 shadow_log.py [logpath|--all]"""
import json, sys, glob, os
from collections import Counter
def logs():
    if len(sys.argv) > 1 and sys.argv[1] != "--all":
        return [sys.argv[1]]
    out = []
    for pat in ["/Users/amansharma/Library/Containers/*/Data/tmp/shadow_ace.log",
                os.path.join(os.environ.get("TMPDIR","/tmp"), "shadow_ace.log")]:
        out += glob.glob(pat)
    return out
fams, evs, sess = Counter(), Counter(), set()
n = 0
for p in logs():
    print("== %s" % p)
    for ln in open(p):
        ln = ln.strip()
        if not ln: continue
        try: o = json.loads(ln)
        except: continue
        n += 1
        sess.add(o.get("sess","?"))
        fams[o.get("fam","?")] += 1
        evs[o.get("fam","?") + "/" + o.get("ev","?")] += 1
        dt = o.get("dt","")
        up = o.get("up_ms","?")
        if o.get("fam") in ("GATE","RIG") or "deny" in o.get("ev","") or "block" in o.get("ev","") or "alias" in o.get("ev",""):
            print("  [%s +%-8s] %s/%s %s" % (dt, str(up)+"ms", o.get("fam"), o.get("ev"), o.get("d","")[:120]))
print("--- sessions=%s total=%d fams=%s" % (sorted(sess), n, dict(fams)))
print("--- top events:")
for k, v in evs.most_common(15): print("  %dx %s" % (v, k))
