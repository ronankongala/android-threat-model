"""android-threat-engine command line entry point.

Usage: python src/ate.py --apk app.apk [--out DIR] [--dynamic] [--no-ai]

Decodes the APK (apk.py), extracts manifest, smali code and taint
findings (surface.py, code_analyzer.py, taint_analyzer.py), writes
<name>-report.json and <name>-report.md to DIR (report.py), and prints one
summary line. <name> is the APK file name without its extension.

With --dynamic, the APK is then installed and exercised on a running emulator
or device over adb (dynamic_analyzer.py). If adb finds no device, a warning is
printed and the dynamic step is skipped; the static report is still written.
"""
import argparse
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import apk  # noqa: E402
import dynamic_analyzer  # noqa: E402
import report  # noqa: E402
import surface  # noqa: E402


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog='ate', description='Attack surface and code findings report for an Android APK.')
    p.add_argument('--apk', required=True, help='path to the APK file')
    p.add_argument('--out', default='.', help='output directory (default: current directory)')
    p.add_argument('--dynamic', action='store_true',
                   help='also run dynamic analysis on a running emulator over adb')
    p.add_argument('--no-ai', action='store_true', help='reserved; has no effect yet')
    return p.parse_args(argv)


def main_activity(manifest):
    """Name of the launcher activity in the manifest dict, or None."""
    for comp in manifest.get('components', []):
        if comp['type'] in ('activity', 'activity-alias') and surface._is_launcher(comp):
            return comp['name']
    return None


def run_dynamic(apk_path, manifest):
    """Dynamic findings, or [] with a warning when no device is attached."""
    adb = dynamic_analyzer.find_adb()
    if not adb or not dynamic_analyzer.device_available(adb):
        print('warning: no emulator or device found by adb; dynamic analysis skipped '
              '(start the ghera27 emulator and check "adb devices")', file=sys.stderr)
        return []
    return dynamic_analyzer.run(apk_path, manifest['package'], main_activity(manifest),
                                adb=adb, manifest=manifest)


def main(argv=None):
    args = parse_args(argv)
    work = tempfile.mkdtemp(prefix='ate-')
    try:
        try:
            manifest = apk.decode(args.apk, work)
        except apk.ApkError as e:
            print('error: %s' % e, file=sys.stderr)
            return 1
        findings = surface.find(manifest)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    dynamic = run_dynamic(args.apk, manifest) if args.dynamic else None
    name = os.path.splitext(os.path.basename(args.apk))[0]
    report.write(findings, name, args.out, dynamic)
    findings = findings + (dynamic or [])
    components = len({(f['component_type'], f['component']) for f in findings})
    print('%d findings in %d components' % (len(findings), components))
    return 0


if __name__ == '__main__':
    sys.exit(main())
