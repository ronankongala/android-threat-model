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
  strict_true_positive, two_app_benign, two_app_secure, readme_findings,
  false_positive_any
where
  true_positive  = 1 if benign_findings > 0 and any Benign finding's CWE matches any
                   of the benchmark's ground-truth CWEs (cwe_ids), either directly,
                   through SECONDARY_CWE (an alternative CWE that names a closely
                   related weakness and is counted as the ground-truth CWE it maps
                   to), or because it is listed in the benchmark's secondary_cwe_ids
                   column (P1-3: CWEs reviewed against the threat model and README
                   as describing this benchmark's own weakness), else 0
  false_positive = 1 if some Secure finding has a CWE that is exactly one of the
                   benchmark's cwe_ids (no SECONDARY_CWE, no secondary_cwe_ids) AND
                   is on the benchmark's vulnerable component (A1-1) and does not
                   have confidence low, else 0
  strict_true_positive = like true_positive, but only cwe_ids count
  false_positive_any = the legacy definition: 1 if secure_findings > 0, else 0
                   (kept so the old precision stays visible next to the new one)

A1-1 false positive rule. A Secure app is fixed for the benchmark's weakness, not
for every weakness, so a finding there is only a false positive when it claims the
benchmark's own weakness (an exact cwe_ids CWE) on the component that carries it.
The component comes from the vulnerable_component column of data/ground-truth.csv
(one or more class names separated by "; "). A finding's "component" (manifest
findings: the component class; code findings: the smali class, e.g.
edu.ksu.cs.benign.MainActivity$1; app-level findings: "(application)") matches when
  - it is the same class as a listed name, or an inner class of it (Outer$Inner
    matches Outer, at any depth);
  - a listed name without a package (no ".") is compared with the finding's simple
    class name (the part after the last "."; inner classes again match their outer);
  - the column is blank or "(application)": every finding matches, so the CWE alone
    decides.
An "(application)" finding therefore does not match a named class. A Secure app that
still exports its launcher activity, or a finding with a related but not exact CWE,
is not a false positive under this rule; it is under false_positive_any.
A count is left blank when the APK is missing or the tool fails; the scores then
treat it as 0 findings, and the reason is printed.

Usage: python tools/evaluate.py [--no-dynamic | --dynamic] [--auto-readme] [--diff-mode] [--out CSV]
       python tools/evaluate.py --rescore [--dynamic] [--diff-mode] [--out CSV]

--no-dynamic (the default) scores the static layers only: manifest rules, smali
code patterns and taint analysis. --dynamic also passes --dynamic to ate.py, so
each APK is exercised on the running emulator.

--auto-readme (Fix E, scored by P1-5) also replays each benchmark's README
exploit steps on the running emulator with tools/readme_runner.py (installs,
launches, taps and adb commands), saves the observations to
data/eval-tmp/<benchmark>/readme-observations.json and turns them into Benign
findings (readme_findings). Only the Benign scenario is scored: the README
replays Benign (and Malicious), and observations from a step that acts on the
Secure app, and from every later step, are ignored (Benign and Secure share a
package name). A README finding is added to the Benign findings only when no
Benign finding with the same issue and CWE is already present; the number
added is the readme_findings column (blank without --auto-readme). These
findings can add true positives but never false positives; numbers from a run
with --auto-readme are therefore not directly comparable with runs without it.

Two-app scoring (P1-4): with --dynamic and an attached device, every benchmark
that has a built Malicious api27 APK is also run through
dynamic_analyzer.run_two_app twice: Benign plus Malicious, whose findings are
added to the Benign findings, and Secure plus Malicious, whose findings are
added to the Secure findings. Running the same scenario against the Secure app
keeps precision honest: a two-app finding that also appears with the fixed app
makes that benchmark a false positive, just like a single-APK finding would.
Two-app findings count toward true_positive like any other Benign finding
(cwe_ids, SECONDARY_CWE and secondary_cwe_ids). Package names, launcher
activities and task affinities come from the decoded manifests (as in
src/ate.py run_dynamic_two_app). The findings are saved to
data/eval-tmp/<benchmark>/two-app-<Benign|Secure>.json and counted in the extra
columns two_app_benign and two_app_secure (blank when the two-app run did not
happen). Without a device the two-app step is skipped with a warning.

--with-malicious (A3-2, off by default) passes the benchmark's Malicious
api27 APK, when it is built, to ate.py as --second-apk for BOTH the Benign and
the Secure run, so the static two-APK rules (shared task affinity, sticky
broadcasts the Malicious app receives) count toward true and false positives
alike. Runs with and without it are not directly comparable.

--out CSV writes the per-benchmark results to CSV instead of
data/evaluation-results.csv. A --rescore run writes a CSV only when --out is given.
--only BENCH (repeatable) restricts the run to the named benchmarks; combine it
with --out so the full results file is not overwritten.

--diff-mode (P-8) scores differential findings only. Both APKs are analyzed
as usual; then a Benign finding is kept only when the Secure APK has no finding
with the same issue, CWE and class (the class compared without its package,
since some Secure apps use another package name, e.g. edu.ksu.cs.secure), and a
Secure finding is kept only when the Benign APK has no such finding. True and
false positives are then scored on what is left, with the definitions above: a
true positive is a ground-truth CWE among the findings the fix removed, a false
positive one among the findings the fix added. When the Secure APK is missing
or the tool failed on it, no difference can be taken and the benchmark is
scored as in the standard mode. Diff mode needs the fixed app, so it measures
whether the tool sees what a fix changed; it is not the precision of the tool
on a single unknown APK, and its numbers are not comparable with the standard
mode. It works with --rescore as well.

--rescore runs nothing: it rescans the reports a previous run left in
data/eval-tmp/<benchmark>/<Benign|Secure>/app-api27-debug-report.json and scores
them against the current ground truth. Without --dynamic, findings whose issue
starts with "dynamic-" are dropped, so the reports of a dynamic run are rescored
as the static layers only; with --dynamic, the saved two-app findings are added;
with --auto-readme, the saved README observations are turned into findings again.
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
SRC = os.path.join(ROOT, 'src')
COLUMNS = ['benchmark', 'category', 'benign_findings', 'secure_findings', 'true_positive', 'false_positive',
           'strict_true_positive', 'two_app_benign', 'two_app_secure', 'readme_findings',
           'false_positive_any']
APPLICATION = '(application)'

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


def parse_components(value):
    """List of class names from a semicolon separated vulnerable_component cell."""
    return [c.strip() for c in (value or '').split(';') if c.strip()]


def load_ground_truth(path=None):
    """{folder: {'category', 'cwes' (cwe_ids), 'secondary' (secondary_cwe_ids),
    'components' (vulnerable_component)}}."""
    gt = {}
    for row in read_csv(path or GROUND_TRUTH):
        gt[row['folder']] = {'category': row['category'], 'cwes': parse_cwes(row['cwe_ids']),
                             'secondary': parse_cwes(row.get('secondary_cwe_ids')),
                             'components': parse_components(row.get('vulnerable_component'))}
    return gt


def component_matches(component, vulnerable):
    """True when a finding's component is one of the vulnerable components.

    vulnerable is the parsed vulnerable_component list. Blank, or only
    "(application)", matches every finding. Otherwise the finding's class (with
    any $Inner suffix removed) must equal a listed fully qualified name, or, for a
    listed name without a package, have that simple name.
    """
    names = [v for v in vulnerable or () if v != APPLICATION]
    if not names:
        return True
    outer = str(component or '').split('$', 1)[0]
    simple = outer.rsplit('.', 1)[-1]
    for name in names:
        if (outer == name) if '.' in name else (simple == name):
            return True
    return False


# Findings at these confidence levels never make a Secure APK a false positive.
FP_IGNORED_CONFIDENCE = ('low',)


def is_false_positive(secure, gt_entry):
    """A1-1: some Secure finding has an exact cwe_ids CWE and is on the
    vulnerable component. Confidence threshold: a finding with confidence low
    does not count (a finding without a confidence key does)."""
    return any(f.get('confidence') not in FP_IGNORED_CONFIDENCE
               and f.get('cwe') in gt_entry['cwes']
               and component_matches(f.get('component'), gt_entry.get('components'))
               for f in secure or [])


def benchmark_list():
    """Benchmarks with a successful api27 build, in build-results.csv order."""
    benchmarks = []
    for row in read_csv(BUILD_RESULTS):
        if row['result'] == 'success' and 'api27' in row['flavor'] and row['benchmark'] not in benchmarks:
            benchmarks.append(row['benchmark'])
    return benchmarks


def merge_new(findings, extra):
    """(findings plus the extra findings whose (issue, cwe) is not yet present,
    the list of those added). Duplicates inside extra are added once."""
    seen = {(f.get('issue'), f.get('cwe')) for f in findings or []}
    added = []
    for f in extra or []:
        key = (f.get('issue'), f.get('cwe'))
        if key not in seen:
            seen.add(key)
            added.append(f)
    return (findings or []) + added, added


def diff_key(finding):
    """(issue, cwe, class without package) used to match a finding of the
    Benign APK with one of the Secure APK (P-8)."""
    component = str(finding.get('component') or '')
    return finding.get('issue'), finding.get('cwe'), component.rsplit('.', 1)[-1]


def diff_findings(benign, secure):
    """P-8: (Benign findings not in Secure, Secure findings not in Benign),
    matched by diff_key. When either list is None (APK missing or tool
    failed) both are returned unchanged."""
    if benign is None or secure is None:
        return benign, secure
    b_keys = {diff_key(f) for f in benign}
    s_keys = {diff_key(f) for f in secure}
    return ([f for f in benign if diff_key(f) not in s_keys],
            [f for f in secure if diff_key(f) not in b_keys])


def score_row(bench, gt_entry, benign, secure, two_app=None, readme=None, diff=False):
    """Score one benchmark; return (CSV row dict, expanded matching CWEs).

    benign and secure are findings lists, or None when the APK was missing or
    the tool failed (the count is then left blank and scored as 0 findings).
    two_app is {'Benign': list or None, 'Secure': list or None} with the
    run_two_app findings (None: not run); they are added to the Benign and the
    Secure findings respectively. readme is the list of README replay findings
    (None: not run); they describe the Benign app and are added to the Benign
    findings only, skipping any whose issue and CWE are already present.
    With diff (P-8, --diff-mode), only the differential findings are scored
    (diff_findings) and the finding counts are those of the differential lists.
    """
    two_app = two_app or {}
    counts = {}
    for variant in ('Benign', 'Secure'):
        extra = two_app.get(variant)
        counts[variant] = '' if extra is None else len(extra)
        if extra:
            if variant == 'Benign':
                benign = (benign or []) + extra
            else:
                secure = (secure or []) + extra
    readme_added = None
    if readme is not None:
        merged, readme_added = merge_new(benign, readme)
        if readme_added:
            benign = merged
    if diff:
        benign, secure = diff_findings(benign, secure)
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
        'false_positive': 1 if is_false_positive(secure, gt_entry) else 0,
        'strict_true_positive': 1 if benign_n > 0 and strict else 0,
        'two_app_benign': counts['Benign'],
        'two_app_secure': counts['Secure'],
        'readme_findings': '' if readme_added is None else len(readme_added),
        'false_positive_any': 1 if secure_n > 0 else 0,
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


def rescore(benchmarks, gt, dynamic=False, tmp=None, auto_readme=False, diff=False):
    """Score the reports a previous run left in `tmp` (default data/eval-tmp),
    without running anything."""
    tmp = tmp or TMP
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
        two_app = None
        if dynamic:
            two_app = {v: load_findings(os.path.join(tmp, bench, 'two-app-%s.json' % v))
                       for v in ('Benign', 'Secure')}
        readme = None
        if auto_readme:
            observations = load_findings(os.path.join(tmp, bench, 'readme-observations.json'))
            if observations is not None:
                import readme_runner
                base = os.path.join(ROOT, 'benchmarks', 'ghera', gt[bench]['category'], bench)
                readme = readme_findings(benign_only(observations), readme_runner.bench_apps(base))
        row, matched = score_row(bench, gt[bench], result['Benign'], result['Secure'], two_app, readme,
                                 diff)
        print('%-58s benign=%-3s secure=%-3s tp=%d strict_tp=%d fp=%d fp_any=%d two_app=%s/%s readme=%s %s'
              % (bench, row['benign_findings'], row['secure_findings'], row['true_positive'],
                 row['strict_true_positive'], row['false_positive'], row['false_positive_any'],
                 row['two_app_benign'],
                 row['two_app_secure'], row['readme_findings'], ', '.join(matched)))
        rows.append(row)
    return rows


def _precision(tp, fp):
    return '%.2f' % (tp / (tp + fp)) if tp + fp else 'n/a'


def summary(rows):
    """Summary lines: TP, FP, precision and recall, expanded and strict, with the
    A1-1 false positives and, for comparison, the legacy "any Secure finding" ones."""
    tp = sum(r['true_positive'] for r in rows)
    fp = sum(r['false_positive'] for r in rows)
    fp_any = sum(r.get('false_positive_any', 0) for r in rows)
    lines = ['Evaluated %d benchmarks: %d true positives, %d false positives '
             '(exact CWE on the vulnerable component; %d with any Secure finding)'
             % (len(rows), tp, fp, fp_any)]
    if rows:
        lines.append('Precision %s, recall %.2f' % (_precision(tp, fp), tp / len(rows)))
        stp = sum(r['strict_true_positive'] for r in rows)
        lines.append('Strict CWE match only (cwe_ids, no secondary CWEs): %d true positives, '
                     'precision %s, recall %.2f' % (stp, _precision(stp, fp), stp / len(rows)))
        lines.append('Legacy precision (false positive = any Secure finding): %s, strict %s'
                     % (_precision(tp, fp_any), _precision(stp, fp_any)))
    return lines


def write_rows(rows, path):
    with open(path, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print('Wrote %s' % os.path.relpath(path, ROOT))


def run_tool(apk, out_dir, dynamic=False, second_apk=None):
    """Return the findings list, or None with a reason when it cannot be produced.
    second_apk is passed to ate.py as --second-apk (--with-malicious)."""
    if not os.path.exists(apk):
        return None, 'APK not found: %s' % os.path.relpath(apk, ROOT)
    os.makedirs(out_dir, exist_ok=True)
    cmd = [sys.executable, ATE, '--apk', apk, '--out', out_dir] + (['--dynamic'] if dynamic else [])
    if second_apk:
        cmd += ['--second-apk', second_apk]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, 'ate.py exit %d: %s' % (r.returncode, (r.stderr or r.stdout).strip())
    report = os.path.join(out_dir, REPORT)
    with open(report, encoding='utf-8') as f:
        findings = json.load(f)
    return findings, r.stdout.strip()


def _src_modules():
    """(apk, ate, dynamic_analyzer) from src/, imported on first use."""
    if SRC not in sys.path:
        sys.path.insert(0, SRC)
    import apk
    import ate
    import dynamic_analyzer
    return apk, ate, dynamic_analyzer


def two_app_device():
    """adb path when a device is attached for the two-app runs, else None."""
    _, _, dynamic_analyzer = _src_modules()
    adb = dynamic_analyzer.find_adb()
    if adb and dynamic_analyzer.device_available(adb):
        return adb
    return None


def run_two_app(app_apk, malicious_apk, adb, save_to=None):
    """dynamic_analyzer.run_two_app with app_apk (Benign or Secure) as the benign
    app and malicious_apk as the malicious one; return (findings or None, message).

    Packages, launcher activities and the benign task affinities come from the
    decoded manifests, as in src/ate.py run_dynamic_two_app. With save_to, the
    findings are written there as JSON (used by --rescore --dynamic).
    """
    apk, ate, dynamic_analyzer = _src_modules()
    for path in (app_apk, malicious_apk):
        if not os.path.exists(path):
            return None, 'APK not found: %s' % os.path.relpath(path, ROOT)
    try:
        man = apk.decode(app_apk)
        mal = apk.decode(malicious_apk)
    except apk.ApkError as e:
        return None, 'cannot decode APK: %s' % e
    findings = dynamic_analyzer.run_two_app(
        app_apk, malicious_apk, man['package'], mal['package'], adb=adb,
        benign_activity=ate.main_activity(man), malicious_activity=ate.main_activity(mal),
        benign_affinities=ate.task_affinities(man))
    if save_to:
        os.makedirs(os.path.dirname(save_to), exist_ok=True)
        with open(save_to, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2)
    return findings, '%d findings (%s with %s)' % (len(findings), man['package'], mal['package'])


def benign_only(observations):
    """The observations before the first step with an action on the Secure app.

    Benign and Secure share a package name, so anything observed once the
    Secure app was installed or started would describe Secure, not Benign.
    """
    kept = []
    for obs in observations:
        if any(a.get('target') == 'Secure' and not str(a.get('status', '')).startswith('skipped')
               for a in obs.get('actions', [])):
            break
        kept.append(obs)
    return kept


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
    scored = benign_only(observations)
    findings = readme_findings(scored, readme_runner.bench_apps(base))
    ran = sum(1 for o in observations if o.get('automatable'))
    msg = '%d README steps, %d automated, %d findings' % (len(observations), ran, len(findings))
    if len(scored) < len(observations):
        msg += ' (steps from %s on act on Secure and are not scored)' % observations[len(scored)].get('step')
    return findings, msg


def main(argv=None):
    p = argparse.ArgumentParser(description='Score src/ate.py against the Ghera ground truth.')
    g = p.add_mutually_exclusive_group()
    g.add_argument('--no-dynamic', dest='dynamic', action='store_false', help='static layers only (default)')
    g.add_argument('--dynamic', dest='dynamic', action='store_true', help='also run dynamic analysis')
    p.set_defaults(dynamic=False)
    p.add_argument('--auto-readme', action='store_true',
                   help='also replay each README exploit on the emulator (tools/readme_runner.py)')
    p.add_argument('--with-malicious', action='store_true',
                   help="pass the benchmark's Malicious APK as --second-apk to the Benign "
                        'and Secure runs (static two-APK rules)')
    p.add_argument('--diff-mode', action='store_true',
                   help='P-8: score only the findings that differ between the Benign and '
                        'Secure APK of each benchmark')
    p.add_argument('--rescore', action='store_true',
                   help='run nothing; rescore the reports already in data/eval-tmp')
    p.add_argument('--out', help='CSV to write (default data/evaluation-results.csv; '
                                 'with --rescore, no CSV unless given)')
    p.add_argument('--only', action='append', metavar='BENCH',
                   help='evaluate only this benchmark (repeatable); use with --out')
    args = p.parse_args(argv)
    gt = load_ground_truth()
    benchmarks = benchmark_list()
    if args.only:
        benchmarks = [b for b in benchmarks if b in args.only]

    if args.rescore:
        print('Rescore of data/eval-tmp (%s)' % ('all findings' if args.dynamic
                                                 else 'static layers only, dynamic-* findings dropped'))
        if args.diff_mode:
            print('Differential mode (--diff-mode): Benign minus Secure, Secure minus Benign')
        rows = rescore(benchmarks, gt, args.dynamic, auto_readme=args.auto_readme,
                       diff=args.diff_mode)
        print('\n' + '\n'.join(summary(rows)))
        if args.out:
            write_rows(rows, args.out)
        return 0

    print('Mode: %s%s' % ('static and dynamic' if args.dynamic else 'static only (--no-dynamic)',
                          ', differential (--diff-mode)' if args.diff_mode else ''))
    if args.with_malicious:
        print('Static two-APK rules on: Malicious APK passed as --second-apk (--with-malicious)')
    print('Benchmarks with a successful api27 build: %d' % len(benchmarks))
    adb = None
    if args.dynamic:
        adb = two_app_device()
        if not adb:
            print('warning: no emulator or device found by adb; two-app scoring skipped')
    rows = []
    for bench in benchmarks:
        if bench not in gt:
            print('skip %s: not in ground-truth.csv' % bench)
            continue
        category = gt[bench]['category']
        base = os.path.join(ROOT, 'benchmarks', 'ghera', category, bench)
        print('== %s/%s (ground truth CWEs: %s)' % (category, bench, ', '.join(sorted(gt[bench]['cwes'])) or 'none'))
        result = {}
        second = os.path.join(base, 'Malicious', APK_REL)
        extra = ({'second_apk': second} if args.with_malicious and os.path.exists(second)
                 else {})
        for variant in ('Benign', 'Secure'):
            findings, msg = run_tool(os.path.join(base, variant, APK_REL),
                                     os.path.join(TMP, bench, variant), args.dynamic, **extra)
            result[variant] = findings
            print('   %-6s %s' % (variant, msg))
            for f in findings or []:
                print('          %s %s %s %s (%s)' % (f['cwe'], f['issue'], f['component_type'],
                                                    f['component'], f['confidence']))
        two_app = None
        malicious = os.path.join(base, 'Malicious', APK_REL)
        if adb and os.path.exists(malicious):
            two_app = {}
            for variant in ('Benign', 'Secure'):
                found, msg = run_two_app(os.path.join(base, variant, APK_REL), malicious, adb,
                                         os.path.join(TMP, bench, 'two-app-%s.json' % variant))
                two_app[variant] = found
                print('   2-app %-6s+Malicious %s' % (variant, msg))
                for f in found or []:
                    print('          %s %s %s %s (%s)' % (f['cwe'], f['issue'], f['component_type'],
                                                        f['component'], f['confidence']))
        for variant in ('Benign', 'Secure'):
            # drop two-app findings of an earlier run so --rescore cannot pick them up
            stale = os.path.join(TMP, bench, 'two-app-%s.json' % variant)
            if (two_app is None or two_app.get(variant) is None) and os.path.exists(stale):
                os.remove(stale)
        if args.auto_readme:
            extra, msg = run_readme(bench, base)
            print('   README %s' % msg)
            for f in extra:
                print('          %s %s %s' % (f['cwe'], f['issue'], f['evidence']))
            readme = extra
        else:
            readme = None
        row, matched = score_row(bench, gt[bench], result['Benign'], result['Secure'], two_app, readme,
                                 args.diff_mode)
        print('   true_positive=%d (matching CWEs: %s) strict_true_positive=%d false_positive=%d '
              'false_positive_any=%d'
              % (row['true_positive'], ', '.join(matched) or 'none', row['strict_true_positive'],
                 row['false_positive'], row['false_positive_any']))
        rows.append(row)

    write_rows(rows, args.out or OUT_CSV)
    print('\n' + '\n'.join(summary(rows)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
