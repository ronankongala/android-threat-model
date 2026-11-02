"""P1-5: README runner scoring in tools/evaluate.py (--auto-readme).
tools/readme_runner.py is mocked, so no device is touched."""
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))

import evaluate  # noqa: E402
import readme_runner  # noqa: E402

BENIGN = 'edu.ksu.cs.benign'
MAL = 'edu.ksu.cs.malicious'
APPS = {'Benign': {'package': BENIGN}, 'Malicious': {'package': MAL}}


def _obs(step, actions, top=None, crashes=()):
    return {'step': step, 'text': 'step %d' % step, 'actions': actions, 'automatable': True,
            'foreground_activity': top, 'signals': {'crashes': list(crashes)}}


def _act(type_, target, status='ok'):
    return {'type': type_, 'target': target, 'status': status}


HIJACK_OBS = _obs(3, [_act('launch', 'Benign')], top=MAL + '/.MalActivity')
CROSSOVER_OBS = _obs(4, [_act('launch', 'Malicious')], top=BENIGN + '/.Secret')


def test_merge_new_dedupes_by_issue_and_cwe():
    have = [{'issue': 'task-affinity-hijack', 'cwe': 'CWE-1021'}]
    extra = [{'issue': 'task-affinity-hijack', 'cwe': 'CWE-1021'},
             {'issue': 'readme-foreground-hijack', 'cwe': 'CWE-1021'},
             {'issue': 'readme-foreground-hijack', 'cwe': 'CWE-1021'}]
    merged, added = evaluate.merge_new(have, extra)
    assert added == [{'issue': 'readme-foreground-hijack', 'cwe': 'CWE-1021'}]
    assert len(merged) == 2
    assert evaluate.merge_new(None, []) == ([], [])


def test_benign_only_stops_at_secure_step():
    secure_step = _obs(5, [_act('install', 'Secure')])
    later = _obs(6, [_act('launch', 'Benign')], top=MAL + '/.MalActivity')
    skipped_secure = _obs(2, [_act('install', 'Secure', 'skipped: no apk')])
    obs = [skipped_secure, HIJACK_OBS, secure_step, later]
    assert evaluate.benign_only(obs) == [skipped_secure, HIJACK_OBS]


def test_score_row_readme_adds_to_benign_only():
    entry = {'category': 'ICC', 'cwes': {'CWE-1021'}, 'secondary': set()}
    found = evaluate.readme_findings([HIJACK_OBS], APPS)
    row, matched = evaluate.score_row('B', entry, [], [], readme=found)
    assert (row['true_positive'], row['false_positive'], row['secure_findings']) == (1, 0, 0)
    assert row['readme_findings'] == 1 and row['benign_findings'] == 1
    assert matched == ['CWE-1021']


def test_score_row_readme_duplicate_not_counted():
    entry = {'category': 'ICC', 'cwes': {'CWE-926'}, 'secondary': set()}
    found = evaluate.readme_findings([CROSSOVER_OBS], APPS)
    benign = [{'issue': 'readme-foreground-crossover', 'cwe': 'CWE-926'}]
    row, _ = evaluate.score_row('B', entry, benign, [], readme=found)
    assert row['readme_findings'] == 0 and row['benign_findings'] == 1


def test_score_row_readme_not_run_is_blank():
    entry = {'category': 'ICC', 'cwes': {'CWE-926'}, 'secondary': set()}
    row, _ = evaluate.score_row('B', entry, [], [])
    assert row['readme_findings'] == ''
    assert evaluate.COLUMNS[-1] == 'readme_findings'


def _setup(tmp_path, monkeypatch, observations):
    bench = tmp_path / 'benchmarks' / 'ghera' / 'ICC' / 'Bench-Lean'
    bench.mkdir(parents=True)
    (bench / 'README.md').write_text('# Summary\n', encoding='utf-8')
    build = tmp_path / 'build.csv'
    build.write_text('benchmark,flavor,result\nBench-Lean,api27,success\n', encoding='utf-8')
    gt = tmp_path / 'gt.csv'
    gt.write_text('category,folder,cwe_ids,secondary_cwe_ids\nICC,Bench-Lean,CWE-1021,\n', encoding='utf-8')
    monkeypatch.setattr(evaluate, 'ROOT', str(tmp_path))
    monkeypatch.setattr(evaluate, 'TMP', str(tmp_path / 'eval-tmp'))
    monkeypatch.setattr(evaluate, 'BUILD_RESULTS', str(build))
    monkeypatch.setattr(evaluate, 'GROUND_TRUTH', str(gt))
    runs = []

    def fake_run_tool(apk, out_dir, dynamic=False):
        runs.append(apk)
        findings = [{'issue': 'exported-no-permission', 'cwe': 'CWE-926', 'component': 'x',
                     'component_type': 'activity', 'confidence': 'high'}]
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, evaluate.REPORT), 'w', encoding='utf-8') as f:
            json.dump(findings, f)
        return findings, 'ok'

    readme_calls = []
    monkeypatch.setattr(evaluate, 'run_tool', fake_run_tool)
    monkeypatch.setattr(readme_runner, 'resolve_adb', lambda adb='adb': None)
    monkeypatch.setattr(readme_runner, 'run_readme',
                        lambda path, **kw: readme_calls.append(path) or observations)
    monkeypatch.setattr(readme_runner, 'bench_apps', lambda base: APPS)
    return readme_calls


def test_main_auto_readme_scores_benign_once(tmp_path, monkeypatch):
    secure_obs = _obs(9, [_act('install', 'Secure')])
    after_secure = _obs(10, [_act('launch', 'Malicious')], top=BENIGN + '/.Secret')
    readme_calls = _setup(tmp_path, monkeypatch, [HIJACK_OBS, HIJACK_OBS, secure_obs, after_secure])
    out = tmp_path / 'res.csv'
    assert evaluate.main(['--auto-readme', '--out', str(out)]) == 0
    assert len(readme_calls) == 1
    row, = list(csv.DictReader(open(out, encoding='utf-8')))
    # one README finding (hijack, deduped); the crossover after the Secure step is ignored
    assert row['readme_findings'] == '1'
    assert row['benign_findings'] == '2' and row['secure_findings'] == '1'
    assert row['true_positive'] == '1' and row['false_positive'] == '1'
    saved = tmp_path / 'eval-tmp' / 'Bench-Lean' / 'readme-observations.json'
    assert len(json.loads(saved.read_text())) == 4
    # --rescore --auto-readme rebuilds the same row from the saved files
    rows = evaluate.rescore(['Bench-Lean'], evaluate.load_ground_truth(), auto_readme=True)
    assert rows[0]['readme_findings'] == 1 and rows[0]['benign_findings'] == 2


def test_main_without_auto_readme_does_not_replay(tmp_path, monkeypatch):
    readme_calls = _setup(tmp_path, monkeypatch, [HIJACK_OBS])
    out = tmp_path / 'res.csv'
    evaluate.main(['--out', str(out)])
    assert readme_calls == []
    row, = list(csv.DictReader(open(out, encoding='utf-8')))
    assert row['readme_findings'] == '' and row['true_positive'] == '0'
