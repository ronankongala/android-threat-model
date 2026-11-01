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
  true_positive  = 1 if benign_findings > 0 and a Benign finding's CWE is one of the
                   benchmark's ground-truth CWEs, else 0
  false_positive = 1 if secure_findings > 0, else 0
A count is left blank when the APK is missing or the tool fails; the scores then
treat it as 0 findings, and the reason is printed.

Usage: python tools/evaluate.py
"""
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
ATE = os.path.join(ROOT, 'src', 'ate.py')
APK_REL = os.path.join('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')
COLUMNS = ['benchmark', 'category', 'benign_findings', 'secure_findings', 'true_positive', 'false_positive']


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


def run_tool(apk, out_dir):
    """Return the findings list, or None with a reason when it cannot be produced."""
    if not os.path.exists(apk):
        return None, 'APK not found: %s' % os.path.relpath(apk, ROOT)
    os.makedirs(out_dir, exist_ok=True)
    r = subprocess.run([sys.executable, ATE, '--apk', apk, '--out', out_dir],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None, 'ate.py exit %d: %s' % (r.returncode, (r.stderr or r.stdout).strip())
    report = os.path.join(out_dir, 'app-api27-debug-report.json')
    with open(report, encoding='utf-8') as f:
        findings = json.load(f)
    return findings, r.stdout.strip()


def main():
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
                                     os.path.join(TMP, bench, variant))
            result[variant] = findings
            print('   %-6s %s' % (variant, msg))
            for f in findings or []:
                print('          %s %s %s %s (%s)' % (f['cwe'], f['issue'], f['component_type'],
                                                    f['component'], f['confidence']))
        benign, secure = result['Benign'], result['Secure']
        benign_n = len(benign) if benign is not None else 0
        secure_n = len(secure) if secure is not None else 0
        matched = sorted({f['cwe'] for f in benign or []} & gt[bench]['cwes'])
        tp = 1 if benign_n > 0 and matched else 0
        fp = 1 if secure_n > 0 else 0
        print('   true_positive=%d (matching CWEs: %s) false_positive=%d' % (tp, ', '.join(matched) or 'none', fp))
        rows.append({
            'benchmark': bench,
            'category': category,
            'benign_findings': '' if benign is None else benign_n,
            'secure_findings': '' if secure is None else secure_n,
            'true_positive': tp,
            'false_positive': fp,
        })

    with open(OUT_CSV, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    tp = sum(r['true_positive'] for r in rows)
    fp = sum(r['false_positive'] for r in rows)
    print('\nEvaluated %d benchmarks: %d true positives, %d false positives' % (len(rows), tp, fp))
    print('Wrote %s' % os.path.relpath(OUT_CSV, ROOT))
    return 0


if __name__ == '__main__':
    sys.exit(main())
