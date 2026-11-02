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
  benchmark, category, benign_findings, secure_findings, true_positive, false_positive,
  strict_true_positive
where
  true_positive  = 1 if benign_findings > 0 and any Benign finding's CWE matches any
                   of the benchmark's ground-truth CWEs (cwe_ids), either directly,
                   through SECONDARY_CWE (an alternative CWE that names a closely
                   related weakness and is counted as the ground-truth CWE it maps
                   to), or because it is listed in the benchmark's secondary_cwe_ids
                   column (P1-3: CWEs reviewed against the threat model and README
                   as describing this benchmark's own weakness), else 0
  false_positive = 1 if secure_findings > 0, else 0
  strict_true_positive = like true_positive, but only cwe_ids count
A count is left blank when the APK is missing or the tool fails; the scores then
treat it as 0 findings, and the reason is printed.

Usage: python tools/evaluate.py [--no-dynamic | --dynamic] [--auto-readme] [--out CSV]
       python tools/evaluate.py --rescore [--dynamic] [--out CSV]

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

--out CSV writes the per-benchmark results to CSV instead of
data/evaluation-results.csv. A --rescore run writes a CSV only when --out is given.

--rescore runs nothing: it rescans the reports a previous run left in
data/eval-tmp/<benchmark>/<Benign|Secure>/app-api27-debug-report.json and scores
them against the current ground truth. Without --dynamic, findings whose issue
starts with "dynamic-" are dropped, so the reports of a dynamic run are rescored
as the static layers only.
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
REPORT = 'app-api27-debug-report.json'
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
# The secondary_cwe_ids column of data/ground-truth.csv lists, per benchmark,
# these keys for its cwe_ids plus the CWEs added by the P1-3 review.
SECONDARY_CWE = {
    'CWE-829': 'CWE-749',
    'CWE-925': 'CWE-926',
    'CWE-360': 'CWE-925',
    'CWE-348': 'CWE-927',
    'CWE-346': 'CWE-927',
    'CWE-441': 'CWE-926',
}


def matching_cwes(finding_cwes, gt_cwes, secondary_cwes=()):
    """Return (strict, expanded) sorted lists of matches.

    strict: finding CWEs that are ground-truth CWEs.
    expanded: strict plus 'found->gt' entries for finding CWEs that map to a
    ground-truth CWE through SECONDARY_CWE, plus 'found(secondary)' entries for
    the other finding CWEs listed in secondary_cwes (the benchmark's
    secondary_cwe_ids column).
    """
    strict = sorted(set(finding_cwes) & gt_cwes)
    expanded = list(strict)
    for c in sorted(set(finding_cwes) - gt_cwes):
        if SECONDARY_CWE.get(c) in gt_cwes:
            expanded.append('%s->%s' % (c, SECONDARY_CWE[c]))
        elif c in secondary_cwes:
            expanded.append('%s(secondary)' % c)
    return strict, expanded


def read_csv(path):
    # build-results.csv is written by Export-Csv with a UTF-8 byte order mark.
    with open(path, encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def parse_cwes(value):
    """Set of CWE ids from a semicolon separated ground-truth cell."""
    return {c.strip() for c in (value or '').split(';') if c.strip()}


def load_ground_truth(path=GROUND_TRUTH):
    """{folder: {'category', 'cwes' (cwe_ids), 'secondary' (secondary_cwe_ids)}}."""
    gt = {}
    for row in read_csv(path):
        gt[row['folder']] = {'category': row['category'], 'cwes': parse_cwes(row['cwe_ids']),
                             'secondary': parse_cwes(row.get('secondary_cwe_ids'))}
    return gt


def benchmark_list():
    """Benchmarks with a successful api27 build, in build-results.csv order."""
    benchmarks = []
    for row in read_csv(BUILD_RESULTS):
        if row['result'] == 'success' and 'api27' in row['flavor'] and row['benchmark'] not in benchmarks:
            benchmarks.append(row['benchmark'])
    return benchmarks


def score_row(bench, gt_entry, benign, secure):
    """Score one benchmark; return (CSV row dict, expanded matching CWEs).

    benign and secure are findings lists, or None when the APK was missing or
    the tool failed (the count is then left blank and scored as 0 findings).
    """
    benign_n = len(benign) if benign is not None else 0
    secure_n = len(secure) if secure is not None else 0
    strict, matched = matching_cwes({f['cwe'] for f in benign or []}, gt_entry['cwes'],
                                    gt_entry.get('secondary', ()))
    row = {
        'benchmark': bench,
        'category': gt_entry['category'],
        'benign_findings': '' if benign is None else benign_n,
        'secure_findings': '' if secure is None else secure_n,
        'true_positive': 1 if benign_n > 0 and matched else 0,
        'false_positive': 1 if secure_n > 0 else 0,
        'strict_true_positive': 1 if benign_n > 0 and strict else 0,
    }
    return row, matched


def load_findings(path):
    """Findings list from a JSON file, or None when the file does not exist."""
    if not os.path.exists(path):
        return None
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def is_dynamic(finding):
    return str(finding.get('issue', '')).startswith('dynamic-')


def rescore(benchmarks, gt, dynamic=False, tmp=TMP):
    """Score the reports a previous run left in `tmp`, without running anything."""
    rows = []
    for bench in benchmarks:
        if bench not in gt:
            print('skip %s: not in ground-truth.csv' % bench)
            continue
        result = {}
        for variant in ('Benign', 'Secure'):
            findings = load_findings(os.path.join(tmp, bench, variant, REPORT))
            if findings is not None and not dynamic:
                findings = [f for f in findings if not is_dynamic(f)]
            result[variant] = findings
        row, matched = score_row(bench, gt[bench], result['Benign'], result['Secure'])
        print('%-58s benign=%-3s secure=%-3s tp=%d strict_tp=%d fp=%d %s'
              % (bench, row['benign_findings'], row['secure_findings'], row['true_positive'],
                 row['strict_true_positive'], row['false_positive'], ', '.join(matched)))
        rows.append(row)
    return rows


def summary(rows):
    """Summary lines: TP, FP, precision and recall, expanded and strict."""
    tp = sum(r['true_positive'] for r in rows)
    fp = sum(r['false_positive'] for r in rows)
    lines = ['Evaluated %d benchmarks: %d true positives, %d false positives' % (len(rows), tp, fp)]
    if rows:
        precision = '%.2f' % (tp / (tp + fp)) if tp + fp else 'n/a'
        lines.append('Precision %s, recall %.2f' % (precision, tp / len(rows)))
        stp = sum(r['strict_true_positive'] for r in rows)
        sprec = '%.2f' % (stp / (stp + fp)) if stp + fp else 'n/a'
        lines.append('Strict CWE match only (cwe_ids, no secondary CWEs): %d true positives, '
                     'precision %s, recall %.2f' % (stp, sprec, stp / len(rows)))
    return lines


def write_rows(rows, path):
    with open(path, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print('Wrote %s' % os.path.relpath(path, ROOT))


def run_tool(apk, out_dir, dynamic=False):
    """Return the findings list, or None with a reason when it cannot be produced."""
    if not os.path.exists(apk):
        return None, 'APK not found: %s' % os.path.relpath(apk, ROOT)
    os.makedirs(out_dir, exist_ok=True)
    cmd = [sys.executable, ATE, '--apk', apk, '--out', out_dir] + (['--dynamic'] if dynamic else [])
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, 'ate.py exit %d: %s' % (r.returncode, (r.stderr or r.stdout).strip())
    report = os.path.join(out_dir, REPORT)
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
    p.add_argument('--rescore', action='store_true',
                   help='run nothing; rescore the reports already in data/eval-tmp')
    p.add_argument('--out', help='CSV to write (default data/evaluation-results.csv; '
                                 'with --rescore, no CSV unless given)')
    args = p.parse_args(argv)
    gt = load_ground_truth()
    benchmarks = benchmark_list()

    if args.rescore:
        print('Rescore of data/eval-tmp (%s)' % ('all findings' if args.dynamic
                                                 else 'static layers only, dynamic-* findings dropped'))
        rows = rescore(benchmarks, gt, args.dynamic)
        print('\n' + '\n'.join(summary(rows)))
        if args.out:
            write_rows(rows, args.out)
        return 0

    print('Mode: %s' % ('static and dynamic' if args.dynamic else 'static only (--no-dynamic)'))
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
        row, matched = score_row(bench, gt[bench], result['Benign'], result['Secure'])
        print('   true_positive=%d (matching CWEs: %s) strict_true_positive=%d false_positive=%d'
              % (row['true_positive'], ', '.join(matched) or 'none', row['strict_true_positive'],
                 row['false_positive']))
        rows.append(row)

    write_rows(rows, args.out or OUT_CSV)
    print('\n' + '\n'.join(summary(rows)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
