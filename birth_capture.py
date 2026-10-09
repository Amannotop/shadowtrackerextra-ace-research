#!/usr/bin/env python3
# birth_capture.py — professional birth-window capture (kill + launch + attach <2s), ShadowTrackerExtra 4.6.0
# language: Python, file: birth_capture.py, runtime: Python 3.9 + Frida 17.22.2 (lab device ONLY)
# *watch for one-shot flags: AnoSDKInit + dispatcher op0 latch at birth — attach latency >3s MISSES them (NOT-OBSERVED, never assumed)*
# *watch for CrashKit observer kill: hooks are log-only, spawn-gated attach, zero return-patching in this rig*
"""Usage: python3 birth_capture.py [--window SECS] [--out DIR]
Kills stale instances, launches via open -a (launchd parentage = valid signature),
polls for the new pid every 100ms, attaches + loads monitor.js immediately.
Streams to stdout + captures/birth-<ts>/monitor.log with per-stage timings."""
import frida, time, sys, os, subprocess, datetime, argparse

def logf(fh, s):
    line = "[%s] %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], s)
    print(line, flush=True)
    fh.write(line + "\n"); fh.flush()

def pids():
    out = subprocess.run(["ps", "aux"], capture_output=True, text=True).stdout
    r = []
    for ln in out.splitlines():
        if "ShadowTrackerExtra" in ln and "grep" not in ln and "/X/" in ln and "lab" not in ln:
            try: r.append(int(ln.split()[1]))
            except: pass
    return r

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=90)
    ap.add_argument("--out", default="/Users/amansharma/Desktop/source/captures")
    a = ap.parse_args()
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    d = os.path.join(a.out, "birth-" + ts); os.makedirs(d, exist_ok=True)
    fh = open(os.path.join(d, "monitor.log"), "w")
    js = open("/Users/amansharma/Desktop/source/monitor.js").read()
    t_start = time.time()
    logf(fh, "rig=birth_capture window=%ds out=%s" % (a.window, d))

    for p in pids():
        try: subprocess.run(["kill", "-9", str(p)], capture_output=True)
        except: pass
    logf(fh, "stage=kill stale instances")
    time.sleep(1)

    subprocess.run(["open", "-a", "Battlegrounds"], capture_output=True)
    t_launch = time.time()
    logf(fh, "stage=launch issued")
    pid = None
    for i in range(100):
        time.sleep(0.1)
        cur = pids()
        if cur:
            pid = cur[0]; break
    if not pid:
        logf(fh, "FATAL NO-PID: no live pid 10s after launch"); fh.close(); sys.exit(2)
    t_found = time.time()
    logf(fh, "stage=pid pid=%d latency=%.2fs post-launch" % (pid, t_found - t_launch))

    dev = frida.get_local_device()
    try:
        sess = dev.attach(pid)
        t_att = time.time()
        logf(fh, "stage=attach OK latency=%.2fs post-launch" % (t_att - t_launch))
    except Exception as e:
        logf(fh, "FATAL ATTACH-FAIL: %s" % str(e)[:300]); fh.close(); sys.exit(4)
    try:
        sc = sess.create_script(js)
        sc.on("message", lambda m, dd: logf(fh, "[frida:%s] %s" % (m.get("type"), m.get("payload") if m.get("type") == "send" else str(m)[:200])))
        sc.load()
        t_load = time.time()
        logf(fh, "stage=load OK hooks-live latency=%.2fs post-launch (drive: login->matchmaking->match-start->120s)" % (t_load - t_launch))
    except Exception as e:
        logf(fh, "FATAL LOAD-FAIL: %s" % str(e)[:300]); fh.close(); sys.exit(5)
    try:
        time.sleep(a.window)
    except KeyboardInterrupt:
        logf(fh, "interrupted by operator")
    logf(fh, "STREAM-DONE total=%.1fs log=%s/monitor.log" % (time.time() - t_start, d))
    try: sess.detach()
    except: pass
    fh.close()

if __name__ == "__main__":
    main()
