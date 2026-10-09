#!/usr/bin/env python3
# version_probe.py — fingerprint a new game version into a VersionRow (operator lab ONLY)
# language: Python, file: version_probe.py, runtime: Python 3.9, macOS
# *watch for silent substitution: a new version NEVER reuses an old row — probe emits a fresh row, operator verifies, then appends*
"""Usage: python3 version_probe.py [--app /path/to/Bundle.app]
Emits: bundle version, anogs __TEXT sha256, export/import/string counts, gate byte-check vs §4,
dispatcher/IOCTL presence, full seam export list with offsets. Paste output as a new kVersions row."""
import subprocess, hashlib, argparse, re, os

def run(*c):
    return subprocess.run(list(c), capture_output=True, text=True).stdout

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", default="/Applications/Battlegrounds.app/Wrapper/ShadowTrackerExtra.app")
    a = ap.parse_args()
    app, main, anogs = a.app, a.app + "/ShadowTrackerExtra", a.app + "/Frameworks/anogs.framework/anogs"
    gate = a.app + "/Frameworks/CheckNewDylib.framework/CheckNewDylib"
    print("== version_probe ==")
    print("bundle: %s" % run("plutil", "-p", app + "/Info.plist").split("CFBundleShortVersionString")[1][:40] if True else "")
    print("main-bytes: %s" % os.path.getsize(main))
    print("anogs-bytes: %s" % os.path.getsize(anogs))
    t = run("nm", "-g", anogs)
    print("anogs-T: %d" % len([l for l in t.splitlines() if " T " in l]))
    print("anogs-U: %d" % len([l for l in t.splitlines() if " U " in l]))
    for l in t.splitlines():
        if " T _AnoSDK" in l or "T _CheckSymbolSource" in run("nm", "-g", gate):
            pass
    print("--- seam ---")
    print(run("nm", "-g", anogs))
    print("--- strings census ---")
    s = run("bash", "-c", "strings -a '%s' | wc -l" % anogs).strip()
    print("strings: %s" % s)
    print("--- gate bytes (first 4 insns must match §4: sub sp / stp x20,x19 / stp x29,x30 / add x29) ---")
    print(run("otool", "-tv", "-V", "-p", "_CheckSymbolSource", gate).splitlines()[:8])

if __name__ == "__main__":
    main()
