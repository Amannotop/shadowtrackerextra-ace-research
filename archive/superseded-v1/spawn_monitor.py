#!/usr/bin/env python3
# spawn_monitor.py — professional launch+attach monitor rig, ShadowTrackerExtra 4.6.0
# language: Python, file: spawn_monitor.py, runtime: Python 3.9 + Frida 17.22.2 (lab device ONLY)
# *watch for spawn-death: dev.spawn = SIGKILL Code Signature Invalid (frida-helper parentage) — NEVER spawn*
# *watch for attach window: hook within seconds of launch, before AnoSDKInit one-shot flags latch (0x29bc10)*
"""Usage: python3 spawn_monitor.py [--window SECS] [--out DIR]
Launches via open -a (launchd parentage preserves signature), attaches to the running
pid, loads monitor.js, streams timestamped lines to stdout + captures/mon-<ts>/monitor.log.
Every stage has a timeout and a named fatal (ATTACH-TIMEOUT / ATTACH-FAIL / LOAD-FAIL)."""
import frida, time, sys, os, subprocess, datetime, argparse

def logf(fh, s):
    line = "[%s] %s" % (datetime.datetime.now().strftime("%H:%M:%S"), s)
    print(line, flush=True)
    fh.write(line + "\n"); fh.flush()

def find_pid():
    out = subprocess.run(["ps", "aux"], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        if "ShadowTrackerExtra" in ln and "grep" not in ln and "/X/" in ln:
            try:
                return int(ln.split()[1])
            except:
                pass
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=75)
    ap.add_argument("--out", default="/Users/amansharma/Desktop/source/captures")
    a = ap.parse_args()
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    d = os.path.join(a.out, "mon-" + ts)
    os.makedirs(d, exist_ok=True)
    fh = open(os.path.join(d, "monitor.log"), "w")
    js = open("/Users/amansharma/Desktop/source/monitor.js").read()
    logf(fh, "rig start window=%ds out=%s" % (a.window, d))

    logf(fh, "stage=launch open -a Battlegrounds ...")
    subprocess.run(["open", "-a", "Battlegrounds"], capture_output=True)
    pid = None
    for _ in range(30):
        time.sleep(1)
        pid = find_pid()
        if pid:
            break
    if not pid:
        logf(fh, "FATAL ATTACH-TIMEOUT: no live pid after 30s")
        fh.close(); sys.exit(2)
    logf(fh, "stage=launch OK pid=%d" % pid)

    dev = frida.get_local_device()
    try:
        logf(fh, "stage=attach pid=%d ..." % pid)
        sess = dev.attach(pid)
        logf(fh, "stage=attach OK")
    except Exception as e:
        logf(fh, "FATAL ATTACH-FAIL: %s" % str(e)[:300])
        fh.close(); sys.exit(4)
    try:
        logf(fh, "stage=load monitor.js ...")
        sc = sess.create_script(js)
        sc.on("message", lambda m, dd: logf(fh, "[frida:%s] %s" % (m.get("type"), m.get("payload") if m.get("type") == "send" else str(m)[:300])))
        sc.load()
        logf(fh, "stage=load OK streaming %ds (drive: login->matchmaking->match-start->120s)" % a.window)
    except Exception as e:
        logf(fh, "FATAL LOAD-FAIL: %s" % str(e)[:300])
        fh.close(); sys.exit(5)
    try:
        time.sleep(a.window)
    except KeyboardInterrupt:
        logf(fh, "interrupted by operator")
    logf(fh, "STREAM-DONE log=%s/monitor.log" % d)
    try:
        sess.detach()
    except:
        pass
    fh.close()

if __name__ == "__main__":
    main()
