"""android-threat-engine command line entry point.

Usage: python src/ate.py --apk app.apk [--out DIR] [--dynamic]
                        [--dynamic-two-app MALICIOUS_APK] [--policy POLICY.txt]
                        [--ml] [--no-ai] [--second-apk APK]

Decodes the APK (apk.py), extracts manifest, smali code and taint
findings (surface.py, code_analyzer.py, taint_analyzer.py), writes
<name>-report.json and <name>-report.md to DIR (report.py), and prints one
summary line. <name> is the APK file name without its extension.

With --dynamic, the APK is then installed and exercised on a running emulator
or device over adb (dynamic_analyzer.py). If adb finds no device, a warning is
printed and the dynamic step is skipped; the static report is still written.

With --dynamic-two-app MALICIOUS_APK, the analyzed APK (the benign app) and
MALICIOUS_APK are installed together; the benign app is started, then the
malicious one, and task hijacks, foreign foreground activities, changes to the
benign app's internal storage and Permission Denial lines are reported
(dynamic_analyzer.run_two_app). The findings go to the same dynamic section of
the report as the --dynamic findings.

With --second-apk APK, APK is decoded too and the static two-APK rules of
surface.py compare it with the analyzed APK (shared task affinity, sticky
broadcasts it receives). No device is needed.

With --policy POLICY.txt, the privacy policy text is compared with the
manifest permissions and the advertising and analytics SDK packages in the APK
(privacy_checker.py). Contradictions are listed in a "Privacy Policy Analysis"
section of the Markdown report and under the "privacy" key of a separate
<name>-privacy.json file.

With --ml, app-level features (exported components, permissions, network,
WebView, SQLite, crypto, file storage and SMS APIs) are computed from the
decoded APK and scored by the logistic regression in data/ml-model.pkl
(ml_layer.py; train it with `python src/ml_layer.py train`). When it predicts
the app vulnerable (probability >= 0.5), one APK-level finding is added:
component "(application)", issue "ml-vulnerable-app", CWE "ML" (the
classifier names no weakness), confidence medium at probability >= 0.75 and
low otherwise, with the probability in the evidence.
"""
import argparse
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import apk  # noqa: E402
import dynamic_analyzer  # noqa: E402
import privacy_checker  # noqa: E402
import report  # noqa: E402
import surface  # noqa: E402


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog='ate', description='Attack surface and code findings report for an Android APK.')
    p.add_argument('--apk', required=True, help='path to the APK file')
    p.add_argument('--out', default='.', help='output directory (default: current directory)')
    p.add_argument('--dynamic', action='store_true',
                   help='also run dynamic analysis on a running emulator over adb')
    p.add_argument('--dynamic-two-app', metavar='MALICIOUS_APK',
                   help='also install MALICIOUS_APK next to the analyzed APK, start both on a '
                        'running emulator and report what it does to the analyzed app')
    p.add_argument('--policy', metavar='POLICY_TXT',
                   help='privacy policy text file to compare with the manifest and SDK packages')
    p.add_argument('--ml', action='store_true',
                   help='also score the APK with the ML classifier in data/ml-model.pkl')
    p.add_argument('--no-ai', action='store_true', help='reserved; has no effect yet')
    p.add_argument('--second-apk', metavar='APK',
                   help='second (for example malicious) APK to compare with statically: '
                        'shared task affinity, sticky broadcasts it receives')
    return p.parse_args(argv)


def main_activity(manifest):
    """Name of the launcher activity in the manifest dict, or None."""
    for comp in manifest.get('components', []):
        if comp['type'] in ('activity', 'activity-alias') and surface._is_launcher(comp):
            return comp['name']
    return None


def _device_adb():
    """Path to adb when a device is attached, else None after a warning."""
    adb = dynamic_analyzer.find_adb()
    if not adb or not dynamic_analyzer.device_available(adb):
        print('warning: no emulator or device found by adb; dynamic analysis skipped '
              '(start the ghera27 emulator and check "adb devices")', file=sys.stderr)
        return None
    return adb


def run_dynamic(apk_path, manifest):
    """Dynamic findings from dynamic_analyzer.run_all (the run() checks plus the
    per-broadcast crash, foreground task and deleted file sweep), or [] with a
    warning when no device is attached."""
    adb = _device_adb()
    if not adb:
        return []
    return dynamic_analyzer.run_all(apk_path, manifest['package'], main_activity(manifest),
                                    adb=adb, manifest=manifest)


def task_affinities(manifest):
    """android:taskAffinity values the app declares (application and activities)."""
    found = [manifest.get('application', {}).get('taskAffinity')]
    found += [c.get('task_affinity') for c in manifest.get('components', [])]
    return sorted({a for a in found if a})


def run_dynamic_two_app(apk_path, manifest, malicious_apk):
    """Findings of dynamic_analyzer.run_two_app with the analyzed APK as the
    benign app and `malicious_apk` as the malicious one, or [] with a warning
    when no device is attached or the malicious APK cannot be decoded."""
    adb = _device_adb()
    if not adb:
        return []
    try:
        mal = apk.decode(malicious_apk)
    except apk.ApkError as e:
        print('warning: cannot read the malicious APK (%s); two-app analysis skipped' % e,
              file=sys.stderr)
        return []
    return dynamic_analyzer.run_two_app(apk_path, malicious_apk, manifest['package'], mal['package'],
                                        adb=adb, benign_activity=main_activity(manifest),
                                        malicious_activity=main_activity(mal),
                                        benign_affinities=task_affinities(manifest))


def main(argv=None):
    args = parse_args(argv)
    policy_text = None
    if args.policy:
        try:
            policy_text = privacy_checker.load_policy(args.policy)
        except OSError as e:
            print('error: cannot read policy file: %s' % e, file=sys.stderr)
            return 1
    privacy = None
    ml_bundle = None
    if args.ml:
        import ml_layer
        try:
            ml_bundle = ml_layer.load_model()
        except (OSError, ValueError) as e:
            print('error: cannot load the ML model (%s); run python src/ml_layer.py train' % e,
                  file=sys.stderr)
            return 1
    work = tempfile.mkdtemp(prefix='ate-')
    try:
        try:
            manifest = apk.decode(args.apk, work)
        except apk.ApkError as e:
            print('error: %s' % e, file=sys.stderr)
            return 1
        second = None
        if args.second_apk:
            try:
                os.makedirs(os.path.join(work, 'second'))
                second = apk.decode(args.second_apk, os.path.join(work, 'second'))
            except apk.ApkError as e:
                print('error: second APK: %s' % e, file=sys.stderr)
                return 1
        findings = surface.find(manifest, second=second) if second else surface.find(manifest)
        if policy_text is not None:
            # Needs the decoded smali folders, so it runs before they are removed.
            privacy = privacy_checker.check(policy_text, manifest)
        if ml_bundle is not None:
            # Also reads the smali folders, so it runs before they are removed.
            pred, prob = ml_layer.predict(manifest, bundle=ml_bundle)
            if pred:
                findings = findings + [ml_layer.finding(prob)]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    dynamic = run_dynamic(args.apk, manifest) if args.dynamic else None
    if args.dynamic_two_app:
        dynamic = (dynamic or []) + run_dynamic_two_app(args.apk, manifest, args.dynamic_two_app)
    name = os.path.splitext(os.path.basename(args.apk))[0]
    report.write(findings, name, args.out, dynamic,
                 privacy=privacy, policy_name=os.path.basename(args.policy) if args.policy else None)
    findings = findings + (dynamic or [])
    components = len({(f['component_type'], f['component']) for f in findings})
    print('%d findings in %d components' % (len(findings), components))
    if privacy is not None:
        print('%d privacy policy contradictions' % len(privacy))
    return 0


if __name__ == '__main__':
    sys.exit(main())
