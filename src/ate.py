"""android-threat-engine command line entry point.

Usage: python src/ate.py --apk app.apk [--out DIR] [--no-ai]

Decodes the APK (apk.py), extracts manifest findings (surface.py), writes
<name>-report.json and <name>-report.md to DIR (report.py), and prints one
summary line. <name> is the APK file name without its extension.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import apk  # noqa: E402
import report  # noqa: E402
import surface  # noqa: E402


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog='ate', description='Manifest attack surface report for an Android APK.')
    p.add_argument('--apk', required=True, help='path to the APK file')
    p.add_argument('--out', default='.', help='output directory (default: current directory)')
    p.add_argument('--no-ai', action='store_true', help='reserved; has no effect yet')
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        manifest = apk.decode(args.apk)
    except apk.ApkError as e:
        print('error: %s' % e, file=sys.stderr)
        return 1
    findings = surface.find(manifest)
    name = os.path.splitext(os.path.basename(args.apk))[0]
    report.write(findings, name, args.out)
    components = len({(f['component_type'], f['component']) for f in findings})
    print('%d findings in %d components' % (len(findings), components))
    return 0


if __name__ == '__main__':
    sys.exit(main())
