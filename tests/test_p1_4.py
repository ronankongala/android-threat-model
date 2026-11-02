"""P1-4: two-app scoring in tools/evaluate.py. dynamic_analyzer.run_two_app and
apk.decode are mocked, so no emulator or apktool is needed."""
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))

import evaluate  # noqa: E402

apk, ate, dynamic_analyzer = evaluate._src_modules()

HIJACK = {'component': 'edu.ksu.cs.benign', 'component_type': 'task', 'issue': 'dynamic-task-hijack',
          'cwe': 'CWE-1021', 'confidence': 'high', 'evidence': 'malicious task holds the affinity'}


def _manifest(package, affinity=None):
    comps = [{'type': 'activity', 'name': package + '.MainActivity', 'exported': True,
              'task_affinity': affinity,
              'intent_filters': [{'actions': ['android.intent.action.MAIN'],
                                  'categories': ['android.intent.category.LAUNCHER']}]}]
    return {'package': package, 'components': comps, 'application': {}}


def _fake_decode(path, workdir=None):
    if 'Malicious' in path:
        return _manifest('edu.ksu.cs.malicious')
    return _manifest('edu.ksu.cs.benign', 'edu.ksu.santos.benign.editImage')


def _apks(tmp_path):
    paths = {}
    for app in ('Benign', 'Secure', 'Malicious'):
        p = tmp_path / 'ICC' / 'Bench-Lean' / app / evaluate.APK_REL
        p.parent.mkdir(parents=True)
        p.write_bytes(b'apk')
        paths[app] = str(p)
    return paths


def test_run_two_app_uses_manifests_and_saves(tmp_path, monkeypatch):
    calls = []

    def fake_run_two_app(benign_apk, malicious_apk, bpkg, mpkg, **kw):
        calls.append((benign_apk, malicious_apk, bpkg, mpkg, kw))
        return [HIJACK]

    monkeypatch.setattr(apk, 'decode', _fake_decode)
    monkeypatch.setattr(dynamic_analyzer, 'run_two_app', fake_run_two_app)
    paths = _apks(tmp_path)
    out = tmp_path / 'tmp' / 'two-app-Benign.json'
    found, msg = evaluate.run_two_app(paths['Benign'], paths['Malicious'], 'adb', str(out))
    assert found == [HIJACK]
    (b, m, bpkg, mpkg, kw), = calls
    assert (b, m, bpkg, mpkg) == (paths['Benign'], paths['Malicious'], 'edu.ksu.cs.benign',
                                  'edu.ksu.cs.malicious')
    assert kw['adb'] == 'adb'
    assert kw['benign_activity'] == 'edu.ksu.cs.benign.MainActivity'
    assert kw['malicious_activity'] == 'edu.ksu.cs.malicious.MainActivity'
    assert kw['benign_affinities'] == ['edu.ksu.santos.benign.editImage']
    assert json.loads(out.read_text()) == [HIJACK]


def test_run_two_app_missing_apk(tmp_path):
    found, msg = evaluate.run_two_app(str(tmp_path / 'no.apk'), str(tmp_path / 'm.apk'), 'adb')
    assert found is None and 'APK not found' in msg


def test_score_row_two_app_tp_and_columns():
    entry = {'category': 'ICC', 'cwes': {'CWE-1021'}, 'secondary': set()}
    row, matched = evaluate.score_row('B', entry, [], [], {'Benign': [HIJACK], 'Secure': []})
    assert matched == ['CWE-1021']
    assert (row['true_positive'], row['strict_true_positive'], row['false_positive']) == (1, 1, 0)
    assert (row['benign_findings'], row['secure_findings']) == (1, 0)
    assert (row['two_app_benign'], row['two_app_secure']) == (1, 0)


def test_score_row_two_app_secure_counts_as_false_positive():
    entry = {'category': 'ICC', 'cwes': {'CWE-1021'}, 'secondary': set()}
    row, _ = evaluate.score_row('B', entry, [], [], {'Benign': [HIJACK], 'Secure': [HIJACK]})
    assert (row['true_positive'], row['false_positive'], row['secure_findings']) == (1, 1, 1)


def test_score_row_without_two_app_leaves_columns_blank():
    entry = {'category': 'ICC', 'cwes': {'CWE-1021'}, 'secondary': set()}
    row, _ = evaluate.score_row('B', entry, None, None)
    assert (row['two_app_benign'], row['two_app_secure']) == ('', '')
    assert row['benign_findings'] == ''


def test_existing_columns_keep_their_order():
    assert evaluate.COLUMNS[:7] == ['benchmark', 'category', 'benign_findings', 'secure_findings',
                                    'true_positive', 'false_positive', 'strict_true_positive']
    assert evaluate.COLUMNS[7:9] == ['two_app_benign', 'two_app_secure']


def _setup_main(tmp_path, monkeypatch, device=True):
    paths = _apks(tmp_path / 'benchmarks' / 'ghera')
    build = tmp_path / 'build.csv'
    build.write_text('benchmark,flavor,result\nBench-Lean,api27,success\n', encoding='utf-8')
    gt = tmp_path / 'gt.csv'
    gt.write_text('category,folder,cwe_ids,secondary_cwe_ids\nICC,Bench-Lean,CWE-1021,\n', encoding='utf-8')
    monkeypatch.setattr(evaluate, 'ROOT', str(tmp_path))
    monkeypatch.setattr(evaluate, 'TMP', str(tmp_path / 'eval-tmp'))
    monkeypatch.setattr(evaluate, 'BUILD_RESULTS', str(build))
    monkeypatch.setattr(evaluate, 'GROUND_TRUTH', str(gt))
    monkeypatch.setattr(evaluate, 'run_tool', lambda apk_path, out, dyn=False: ([], 'ok'))
    monkeypatch.setattr(evaluate, 'two_app_device', lambda: 'adb' if device else None)
    monkeypatch.setattr(apk, 'decode', _fake_decode)
    calls = []

    def fake_run_two_app(benign_apk, malicious_apk, bpkg, mpkg, **kw):
        calls.append(benign_apk)
        return [HIJACK] if os.sep + 'Benign' + os.sep in benign_apk else []

    monkeypatch.setattr(dynamic_analyzer, 'run_two_app', fake_run_two_app)
    return paths, calls


def test_main_dynamic_runs_benign_and_secure_with_malicious(tmp_path, monkeypatch):
    paths, calls = _setup_main(tmp_path, monkeypatch)
    out = tmp_path / 'res.csv'
    assert evaluate.main(['--dynamic', '--out', str(out)]) == 0
    assert calls == [paths['Benign'], paths['Secure']]
    row, = list(csv.DictReader(open(out, encoding='utf-8')))
    assert row['true_positive'] == '1' and row['false_positive'] == '0'
    assert (row['two_app_benign'], row['two_app_secure']) == ('1', '0')
    saved = tmp_path / 'eval-tmp' / 'Bench-Lean' / 'two-app-Benign.json'
    assert json.loads(saved.read_text()) == [HIJACK]
    # the saved two-app findings are part of a --rescore --dynamic run
    rows = evaluate.rescore(['Bench-Lean'], evaluate.load_ground_truth(), dynamic=True)
    assert rows[0]['two_app_benign'] == 1


def test_main_static_or_no_device_skips_two_app(tmp_path, monkeypatch):
    _, calls = _setup_main(tmp_path, monkeypatch, device=False)
    out = tmp_path / 'res.csv'
    evaluate.main(['--dynamic', '--out', str(out)])
    evaluate.main(['--out', str(out)])
    assert calls == []
    row, = list(csv.DictReader(open(out, encoding='utf-8')))
    assert row['two_app_benign'] == '' and row['true_positive'] == '0'
