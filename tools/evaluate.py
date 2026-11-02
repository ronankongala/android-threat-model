#!/usr/bin/env python3
"""Run the analysis tool on built Ghera APKs and score it against the ground truth.

For each row of data/build-results.csv with result "success" and a flavor that
contains "api27", runs

    python src/ate.py --apk <apk> --out data/eval-tmp/<benchmark>/<variant>/

on the Benign and Secure APKs at
benchmarks/ghera/<category>/<benchmark>/<variant>/app/build/outputs/apk/api27/debug/app-api27-debug.apk
(category comes from data/ground-truth.csv). Each run gets its own output folder
because every APK has the same file name and the reports would overwrite each other.

Writes data/evaluation-results.csv with the columns
  benchmark, category, benign_findings, secure_findings, true_positive, false_positive
where
  true_positive  = 1 if benign_findings > 0 and any Benign finding's CWE matches any
                   of the benchmark's ground-truth CWEs, either directly or through
                   SECONDARY_CWE (an alternative CWE that names a closely related
                   weakness and is counted as the ground-truth CWE it maps to), else 0
  false_positive = 1 if secure_findings > 0, else 0
A count is left blank when the APK is missing or the tool fails; the scores then
treat it as 0 findings, and the reason is printed.

Usage: python tools/evaluate.py [--no-dynamic | --dynamic] [--auto-readme]

--no-dynamic (the default) scores the static layers only: manifest rules, smali
code patterns and taint analysis. --dynamic also passes --dynamic to ate.py, so
each APK is exercised on the running emulator.

--auto-readme (Fix E) also replays each benchmark's README exploit steps on the
running emulator with tools/readme_runner.py (installs, launches, taps and adb
commands), saves the observations to data/eval-tmp/<benchmark>/readme-observations.json
and turns them into Benign findings (readme_findings). The README steps exercise
the Benign app only, so these findings can add true positives but never false
positives; numbers from a run with --auto-readme are therefore not directly
comparable with runs without it.
"""
import argparse
import csv
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_RESULTS = os.path.join(ROOT, 'data', 'build-results.csv')
GROUND_TRUTH = os.path.join(ROOT, 'data', 'ground-truth.csv')
OUT_CSV = os.path.join(ROOT, 'data', 'evaluation-results.csv')
TMP = os.path.join(ROOT, 'data', 'eval-tmp')
sys.path.insert(0, os.path.join(ROOT, 'tools'))
ATE = os.path.join(ROOT, 'src', 'ate.py')
APK_REL = os.path.join('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')
COLUMNS = ['benchmark', 'category', 'benign_findings', 'secure_findings', 'true_positive', 'false_positive',
           'strict_true_positive']

# Fix A: alternative CWEs that the rules report for a weakness the ground truth
# records under a related CWE. A finding with the key CWE counts as the value CWE.
#   CWE-829 (inclusion of functionality from untrusted control sphere)
#       -> CWE-749 (exposed dangerous method), e.g. webview_file_access
#   CWE-925 (improper verification of intent by broadcast receiver)
#       -> CWE-926 (improper export of components)
#   CWE-360 (trust of system event data) -> CWE-925
#   CWE-348 (use of less trusted source) -> CWE-927 (sensitive data in implicit intent)
#   CWE-346 (origin validation error)    -> CWE-927
#   CWE-441 (unintended proxy / confused deputy) -> CWE-926
# The mapping is applied one step only (CWE-360 counts as CWE-925, not CWE-926).
SECONDARY_CWE = {
    'CWE-829': 'CWE-749',
    'CWE-925': 'CWE-926',
    'CWE-360': 'CWE-925',
    'CWE-348': 'CWE-927',
    'CWE-346': 'CWE-927',
    'CWE-441': 'CWE-926',
}


def matching_cwes(finding_cwes, gt_cwes):
    """Return (strict, expanded) sorted lists of matches.

    strict: finding CWEs that are ground-truth CWEs.
    expanded: strict plus 'found->gt' entries for finding CWEs that map to a
    ground-truth CWE through SECONDARY_CWE.
    """
    strict = sorted(set(finding_cwes) & gt_cwes)
    expanded = list(strict)
    for c in sorted(set(finding_cwes) - gt_cwes):
        if SECONDARY_CWE.get(c) in gt_cwes:
            expanded.append('%s->%s' % (c, SECONDARY_CWE[c]))
    return strict, expanded


def read_csv(path):
    # build-results.csv is written by Export-Csv with a UTF-8 byte order mark.
    with open(path, encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def load_ground_truth():
    gt = {}
    for row in read_csv(GROUND_TRUTH):
        cwes = {c.strip() for c in row['cwe_ids'].split(';') if c.strip()}
        gt[row['folder']] = {'category': row['category'], 'cwes': cwes}
    return gt


def run_tool(apk, out_dir, dynamic=False):
    """Return the findings list, or None with a reason when it cannot be produced."""
    if not os.path.exists(apk):
        return None, 'APK not found: %s' % os.path.relpath(apk, ROOT)
    os.makedirs(out_dir, exist_ok=True)
    cmd = [sys.executable, ATE, '--apk', apk, '--out', out_dir] + (['--dynamic'] if dynamic else [])
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, 'ate.py exit %d: %s' % (r.returncode, (r.stderr or r.stdout).strip())
    report = os.path.join(out_dir, 'app-api27-debug-report.json')
    with open(report, encoding='utf-8') as f:
        findings = json.load(f)
    return findings, r.stdout.strip()


def readme_findings(observations, apps):
    """Findings from tools/readme_runner.py observations (--auto-readme).

    apps is readme_runner.bench_apps(): {app name: {'package', ...}}. Reported:
      readme-benign-crash (CWE-248): a crash line names the Benign package
      readme-foreground-hijack (CWE-1021): a Malicious activity is on top right
          after a step that launched Benign
      readme-foreground-crossover (CWE-926): a Benign activity is on top after a
          step that only launched or tapped in Malicious
    Permission denials and SecurityExceptions are not findings: they usually mean
    the exploit was blocked.
    """
    benign = (apps.get('Benign') or {}).get('package')
    malicious = (apps.get('Malicious') or {}).get('package')
    found = {}

    def add(issue, cwe, obs, detail):
        found.setdefault(issue, {
            'component': benign or '(application)', 'component_type': 'application',
            'issue': issue, 'cwe': cwe, 'confidence': 'medium',
            'evidence': 'README step %s (%s): %s' % (obs.get('step'), obs.get('text', '')[:120], detail),
        })

    for obs in observations:
        acts = [a for a in obs.get('actions', []) if a.get('status') == 'ok']
        targets = {a.get('target') for a in acts if a.get('type') in ('launch', 'tap')}
        top = obs.get('foreground_activity') or ''
        top_pkg = top.split('/')[0]
        for line in (obs.get('signals') or {}).get('crashes', []):
            if benign and benign in line:
                add('readme-benign-crash', 'CWE-248', obs, line.strip())
                break
        if malicious and top_pkg == malicious and any(
                a.get('type') == 'launch' and a.get('target') == 'Benign' for a in acts):
            add('readme-foreground-hijack', 'CWE-1021', obs, 'foreground ' + top)
        if benign and top_pkg == benign and targets == {'Malicious'}:
            add('readme-foreground-crossover', 'CWE-926', obs, 'foreground ' + top)
    return list(found.values())


def run_readme(bench, base):
    """Replay the benchmark README (Fix E); return (findings, message)."""
    import readme_runner
    readme = os.path.join(base, 'README.md')
    if not os.path.exists(readme):
        return [], 'README not found'
    adb = readme_runner.resolve_adb()
    if adb:
        # Ghera apps share package names; start each benchmark from a clean device.
        for pkg in ('edu.ksu.cs.benign', 'edu.ksu.cs.malicious'):
            subprocess.run([adb, 'uninstall', pkg], capture_output=True, text=True)
    observations = readme_runner.run_readme(readme)
    out_dir = os.path.join(TMP, bench)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, 'readme-observations.json'), 'w', encoding='utf-8') as f:
        json.dump(observations, f, indent=2)
    findings = readme_findings(observations, readme_runner.bench_apps(base))
    ran = sum(1 for o in observations if o.get('automatable'))
    return findings, '%d README steps, %d automated, %d findings' % (len(observations), ran, len(findings))


def main(argv=None):
    p = argparse.ArgumentParser(description='Score src/ate.py against the Ghera ground truth.')
    g = p.add_mutually_exclusive_group()
    g.add_argument('--no-dynamic', dest='dynamic', action='store_false', help='static layers only (default)')
    g.add_argument('--dynamic', dest='dynamic', action='store_true', help='also run dynamic analysis')
    p.set_defaults(dynamic=False)
    p.add_argument('--auto-readme', action='store_true',
                   help='also replay each README exploit on the emulator (tools/readme_runner.py)')
    args = p.parse_args(argv)
    print('Mode: %s' % ('static and dynamic' if args.dynamic else 'static only (--no-dynamic)'))
    gt = load_ground_truth()
    benchmarks = []
    for row in read_csv(BUILD_RESULTS):
        if row['result'] == 'success' and 'api27' in row['flavor'] and row['benchmark'] not in benchmarks:
            benchmarks.append(row['benchmark'])
    print('Benchmarks with a successful api27 build: %d' % len(benchmarks))

    rows = []
    for bench in benchmarks:
        if bench not in gt:
            print('skip %s: not in ground-truth.csv' % bench)
            continue
        category = gt[bench]['category']
        base = os.path.join(ROOT, 'benchmarks', 'ghera', category, bench)
        print('== %s/%s (ground truth CWEs: %s)' % (category, bench, ', '.join(sorted(gt[bench]['cwes'])) or 'none'))
        result = {}
        for variant in ('Benign', 'Secure'):
            findings, msg = run_tool(os.path.join(base, variant, APK_REL),
                                     os.path.join(TMP, bench, variant), args.dynamic)
            result[variant] = findings
            print('   %-6s %s' % (variant, msg))
            for f in findings or []:
                print('          %s %s %s %s (%s)' % (f['cwe'], f['issue'], f['component_type'],
                                                    f['component'], f['confidence']))
        if args.auto_readme:
            extra, msg = run_readme(bench, base)
            print('   README %s' % msg)
            for f in extra:
                print('          %s %s %s' % (f['cwe'], f['issue'], f['evidence']))
            if extra:
                result['Benign'] = (result['Benign'] or []) + extra
        benign, secure = result['Benign'], result['Secure']
        benign_n = len(benign) if benign is not None else 0
        secure_n = len(secure) if secure is not None else 0
        strict, matched = matching_cwes({f['cwe'] for f in benign or []}, gt[bench]['cwes'])
        tp = 1 if benign_n > 0 and matched else 0
        strict_tp = 1 if benign_n > 0 and strict else 0
        fp = 1 if secure_n > 0 else 0
        print('   true_positive=%d (matching CWEs: %s) strict_true_positive=%d false_positive=%d'
              % (tp, ', '.join(matched) or 'none', strict_tp, fp))
        rows.append({
            'benchmark': bench,
            'category': category,
            'benign_findings': '' if benign is None else benign_n,
            'secure_findings': '' if secure is None else secure_n,
            'true_positive': tp,
            'false_positive': fp,
            'strict_true_positive': strict_tp,
        })

    with open(OUT_CSV, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    tp = sum(r['true_positive'] for r in rows)
    fp = sum(r['false_positive'] for r in rows)
    print('\nEvaluated %d benchmarks: %d true positives, %d false positives' % (len(rows), tp, fp))
    if rows:
        precision = '%.2f' % (tp / (tp + fp)) if tp + fp else 'n/a'
        print('Precision %s, recall %.2f' % (precision, tp / len(rows)))
        stp = sum(r['strict_true_positive'] for r in rows)
        sprec = '%.2f' % (stp / (stp + fp)) if stp + fp else 'n/a'
        print('Strict CWE match only (no SECONDARY_CWE): %d true positives, precision %s, recall %.2f'
              % (stp, sprec, stp / len(rows)))
    print('Wrote %s' % os.path.relpath(OUT_CSV, ROOT))
    return 0


if __name__ == '__main__':
    sys.exit(main())
