#!/usr/bin/env python3
"""Drift study: which findings each Benign APK produces on each API level.

For every benchmark with a successful api27 build (data/build-results.csv), the
Benign api27 APK is analyzed with src/ate.py. The static layers (manifest
rules, code patterns, taint) do not depend on the device, so they are counted
once. The dynamic layer (src/ate.py --dynamic) is run on one emulator per API
level: for each system image installed under $ANDROID_SDK_ROOT/system-images
(android-<api>/google_apis/x86) an AVD named ghera<api> is used. A missing AVD
is created with tools/create_avds.ps1, and the AVD is booted when no running
device has that API level. Dynamic findings are the ones whose issue starts
with "dynamic-".

Each dynamic finding is keyed by (issue, component, cwe). Against the api27
baseline, new_dynamic_findings lists keys seen on that level but not on api27,
and lost_dynamic_findings keys seen on api27 but not on that level (both
semicolon separated; empty on the api27 rows).

Writes
  data/drift-matrix-results.csv  benchmark, api_level, static_findings_count,
                                 dynamic_findings_count, new_dynamic_findings,
                                 lost_dynamic_findings
  data/drift-static-patterns.csv benchmark, static_findings_count, patterns
                                 (the static issues that fired, with counts)

Usage: python tools/drift_study.py [--reuse-eval | --static-only] [--levels 27 30 ...]

--reuse-eval reads the api27 reports that `tools/evaluate.py --dynamic` left in
data/eval-tmp/<benchmark>/Benign/ instead of running ate.py again on api27.

--static-only records the static layers only, from the reports that
`tools/evaluate.py --no-dynamic` left in data/eval-tmp/, with no emulator. Each
benchmark gets one api27 row whose dynamic columns are blank (not measured).
"""
import argparse
import collections
import csv
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import evaluate  # noqa: E402
import dynamic_analyzer  # noqa: E402

SDK = os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('ANDROID_HOME') or r'C:\Android\Sdk'
OUT_CSV = os.path.join(ROOT, 'data', 'drift-matrix-results.csv')
PATTERNS_CSV = os.path.join(ROOT, 'data', 'drift-static-patterns.csv')
TMP = os.path.join(ROOT, 'data', 'drift-tmp')
EVAL_TMP = os.path.join(ROOT, 'data', 'eval-tmp')
REPORT = 'app-api27-debug-report.json'
COLUMNS = ['benchmark', 'api_level', 'static_findings_count', 'dynamic_findings_count',
           'new_dynamic_findings', 'lost_dynamic_findings']
BOOT_TIMEOUT = 300


def installed_levels():
    """API levels with an installed google_apis x86 system image."""
    base = os.path.join(SDK, 'system-images')
    levels = []
    for name in os.listdir(base) if os.path.isdir(base) else []:
        if name.startswith('android-') and name[8:].isdigit() and \
                os.path.isdir(os.path.join(base, name, 'google_apis', 'x86')):
            levels.append(int(name[8:]))
    return sorted(levels)


def benchmarks():
    gt = evaluate.load_ground_truth()
    out = []
    for row in evaluate.read_csv(evaluate.BUILD_RESULTS):
        b = row['benchmark']
        if row['result'] == 'success' and 'api27' in row['flavor'] and b in gt and b not in out:
            out.append(b)
    return [(b, gt[b]['category']) for b in out]


def is_dynamic(f):
    return f.get('issue', '').startswith('dynamic-')


def key(f):
    return '%s|%s|%s' % (f.get('issue'), f.get('component'), f.get('cwe'))


def device_level(adb, serial):
    r = subprocess.run([adb, '-s', serial, 'shell', 'getprop', 'ro.build.version.sdk'],
                       capture_output=True, text=True, timeout=30)
    return int(r.stdout.strip()) if r.stdout.strip().isdigit() else None


def running_devices(adb):
    r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=30)
    return [ln.split()[0] for ln in r.stdout.splitlines()[1:] if ln.strip().endswith('device')]


def ensure_device(adb, level):
    """Serial of a running device with API `level`, booting ghera<level> if needed."""
    for serial in running_devices(adb):
        if device_level(adb, serial) == level:
            return serial
    avd = 'ghera%d' % level
    emulator = os.path.join(SDK, 'emulator', 'emulator')
    listed = subprocess.run([emulator, '-list-avds'], capture_output=True, text=True).stdout.split()
    if avd not in listed:
        subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-File',
                        os.path.join(ROOT, 'tools', 'create_avds.ps1'), '-ApiLevels', str(level)])
    subprocess.Popen([emulator, '-avd', avd, '-no-window', '-no-snapshot', '-no-audio'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + BOOT_TIMEOUT
    while time.time() < deadline:
        for serial in running_devices(adb):
            if device_level(adb, serial) == level:
                r = subprocess.run([adb, '-s', serial, 'shell', 'getprop', 'sys.boot_completed'],
                                   capture_output=True, text=True, timeout=30)
                if r.stdout.strip() == '1':
                    return serial
        time.sleep(5)
    return None


def analyze(apk, out_dir, dynamic, serial=None):
    env = dict(os.environ)
    if serial:
        env['ANDROID_SERIAL'] = serial
    os.makedirs(out_dir, exist_ok=True)
    cmd = [sys.executable, evaluate.ATE, '--apk', apk, '--out', out_dir] + (['--dynamic'] if dynamic else [])
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        print('   ate.py exit %d: %s' % (r.returncode, (r.stderr or r.stdout).strip()[:200]))
        return None
    with open(os.path.join(out_dir, REPORT), encoding='utf-8') as f:
        return json.load(f)


def write_patterns(benches, static, patterns):
    with open(PATTERNS_CSV, 'w', encoding='utf-8', newline='') as f:
        w = csv.writer(f)
        w.writerow(['benchmark', 'static_findings_count', 'patterns'])
        for bench, _ in benches:
            if bench in patterns:
                w.writerow([bench, static[bench],
                            '; '.join('%s x%d' % kv for kv in sorted(patterns[bench].items()))])


def static_only():
    benches = benchmarks()
    static, patterns, rows = {}, {}, []
    for bench, _ in benches:
        path = os.path.join(EVAL_TMP, bench, 'Benign', REPORT)
        if not os.path.exists(path):
            print('   %s: no report' % bench)
            continue
        with open(path, encoding='utf-8') as f:
            st = [x for x in json.load(f) if not is_dynamic(x)]
        static[bench] = len(st)
        patterns[bench] = collections.Counter(x.get('issue') for x in st)
        rows.append({'benchmark': bench, 'api_level': 27, 'static_findings_count': len(st),
                     'dynamic_findings_count': '', 'new_dynamic_findings': '',
                     'lost_dynamic_findings': ''})
    with open(OUT_CSV, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    write_patterns(benches, static, patterns)
    print('Static only: wrote %s (%d rows, dynamic columns not measured) and %s'
          % (os.path.relpath(OUT_CSV, ROOT), len(rows), os.path.relpath(PATTERNS_CSV, ROOT)))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--reuse-eval', action='store_true',
                   help='use the api27 reports left by tools/evaluate.py --dynamic')
    p.add_argument('--static-only', action='store_true',
                   help='static layers only, from the reports of tools/evaluate.py --no-dynamic')
    p.add_argument('--levels', type=int, nargs='*', help='API levels (default: installed images)')
    args = p.parse_args(argv)
    if args.static_only:
        return static_only()
    levels = args.levels or installed_levels()
    print('API levels with an installed system image: %s' % (', '.join(map(str, levels)) or 'none'))
    adb = dynamic_analyzer.find_adb()
    benches = benchmarks()
    print('Benchmarks with a successful api27 build: %d' % len(benches))

    static, dyn = {}, collections.defaultdict(dict)   # dyn[level][bench] = set of keys
    patterns = {}
    for level in [27] + [lv for lv in levels if lv != 27]:
        if level not in levels:
            print('API 27 image not installed; no baseline')
            continue
        serial = None
        if not (level == 27 and args.reuse_eval):
            serial = ensure_device(adb, level) if adb else None
            if not serial:
                print('API %d: no device could be started; level skipped' % level)
                continue
        for bench, category in benches:
            apk = os.path.join(ROOT, 'benchmarks', 'ghera', category, bench, 'Benign', evaluate.APK_REL)
            if level == 27 and args.reuse_eval:
                path = os.path.join(EVAL_TMP, bench, 'Benign', REPORT)
                findings = json.load(open(path, encoding='utf-8')) if os.path.exists(path) else None
            else:
                findings = analyze(apk, os.path.join(TMP, str(level), bench), True, serial)
            if findings is None:
                print('   %s api%d: no report' % (bench, level))
                continue
            dyn[level][bench] = {key(f) for f in findings if is_dynamic(f)}
            if bench not in static:
                st = [f for f in findings if not is_dynamic(f)]
                static[bench] = len(st)
                patterns[bench] = collections.Counter(f.get('issue') for f in st)
            print('   %s api%d: %d static, %d dynamic' % (bench, level, static[bench], len(dyn[level][bench])))

    rows = []
    base = dyn.get(27, {})
    for bench, _ in benches:
        for level in sorted(dyn):
            if bench not in dyn[level]:
                continue
            cur = dyn[level][bench]
            ref = base.get(bench, set())
            rows.append({
                'benchmark': bench, 'api_level': level,
                'static_findings_count': static.get(bench, ''),
                'dynamic_findings_count': len(cur),
                'new_dynamic_findings': '' if level == 27 else ';'.join(sorted(cur - ref)),
                'lost_dynamic_findings': '' if level == 27 else ';'.join(sorted(ref - cur)),
            })
    with open(OUT_CSV, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    write_patterns(benches, static, patterns)
    print('Wrote %s (%d rows) and %s' % (os.path.relpath(OUT_CSV, ROOT), len(rows),
                                         os.path.relpath(PATTERNS_CSV, ROOT)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
