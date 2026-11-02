"""A5-2: the --ml flag of src/ate.py and the APK-level combined scoring of
src/ml_layer.py. apk.decode is replaced by a stub that writes a small decoded
folder, and the model is a tiny pipeline fit on synthetic rows."""
import csv
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk  # noqa: E402
import ate  # noqa: E402
import ml_layer  # noqa: E402

MANIFEST = {
    'package': 'com.ex', 'permissions': ['android.permission.INTERNET'], 'declared_permissions': [],
    'components': [{'name': 'com.ex.Main', 'type': 'activity', 'exported': False, 'intent_filters': [],
                    'permission': None}],
    'min_sdk': 21, 'target_sdk': 27, 'application': {},
}


def _model(path, vulnerable_when_webview):
    """Save a model bundle that predicts label 1 exactly when has_webview is
    1 (or exactly when it is 0)."""
    joblib = pytest.importorskip('joblib')
    rows, labels = [], []
    for i in range(20):
        feats = dict.fromkeys(ml_layer.FEATURES, 0)
        feats['has_webview'] = i % 2
        rows.append(ml_layer.vector(feats))
        labels.append(int((i % 2) == int(vulnerable_when_webview)))
    model = ml_layer.make_model().fit(rows, labels)
    joblib.dump({'model': model, 'features': ml_layer.FEATURES}, path)


@pytest.fixture
def stub_decode(monkeypatch):
    def decode(apk_path, workdir=None):
        decoded = os.path.join(workdir, 'decoded')
        os.makedirs(os.path.join(decoded, 'smali', 'com', 'ex'))
        with open(os.path.join(decoded, 'smali', 'com', 'ex', 'Main.smali'), 'w') as f:
            f.write('.class public Lcom/ex/Main;\nnew-instance v0, Landroid/webkit/WebView;\n')
        return dict(MANIFEST, decoded_dir=decoded)
    monkeypatch.setattr(apk, 'decode', decode)


def _run(tmp_path, monkeypatch, model_path, extra=()):
    monkeypatch.setattr(ml_layer, 'MODEL', str(model_path))
    out = tmp_path / 'out'
    assert ate.main(['--apk', 'x.apk', '--out', str(out)] + list(extra)) == 0
    with open(out / 'x-report.json') as f:
        return [f for f in json.load(f) if f['issue'] == 'ml-vulnerable-app']


def test_ml_flag_adds_app_finding(tmp_path, monkeypatch, stub_decode):
    _model(tmp_path / 'm.pkl', vulnerable_when_webview=True)
    found = _run(tmp_path, monkeypatch, tmp_path / 'm.pkl', ['--ml'])
    assert len(found) == 1
    f = found[0]
    assert f['component'] == '(application)' and f['cwe'] == 'ML'
    assert f['confidence'] in ('low', 'medium') and 'P(vulnerable) = ' in f['evidence']


def test_ml_flag_no_finding_when_predicted_secure(tmp_path, monkeypatch, stub_decode):
    _model(tmp_path / 'm.pkl', vulnerable_when_webview=False)
    assert _run(tmp_path, monkeypatch, tmp_path / 'm.pkl', ['--ml']) == []


def test_without_ml_flag_no_finding(tmp_path, monkeypatch, stub_decode):
    _model(tmp_path / 'm.pkl', vulnerable_when_webview=True)
    assert _run(tmp_path, monkeypatch, tmp_path / 'm.pkl') == []


def test_ml_flag_missing_model(tmp_path, monkeypatch, stub_decode):
    monkeypatch.setattr(ml_layer, 'MODEL', str(tmp_path / 'missing.pkl'))
    assert ate.main(['--apk', 'x.apk', '--out', str(tmp_path), '--ml']) == 1


def test_finding_confidence():
    assert ml_layer.finding(0.9)['confidence'] == 'medium'
    assert ml_layer.finding(0.6)['confidence'] == 'low'


def _csv(path, rows):
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def test_combined(tmp_path):
    ev = tmp_path / 'eval.csv'
    oof = tmp_path / 'oof.csv'
    _csv(ev, [{'benchmark': 'a', 'true_positive': 1, 'false_positive': 0},
              {'benchmark': 'b', 'true_positive': 0, 'false_positive': 0},
              {'benchmark': 'c', 'true_positive': 0, 'false_positive': 1},
              {'benchmark': 'd', 'true_positive': 0, 'false_positive': 0}])
    _csv(oof, [{'benchmark': b, 'variant': v, 'label': int(v == 'Benign'), 'prob': 0, 'pred': p}
               for b, v, p in [('a', 'Benign', 0), ('a', 'Secure', 1), ('b', 'Benign', 1),
                               ('b', 'Secure', 0), ('c', 'Benign', 1), ('c', 'Secure', 1)]])
    res = ml_layer.combined(str(ev), str(oof))
    assert (res['rules']['tp'], res['rules']['fp']) == (1, 1)
    assert (res['ml']['tp'], res['ml']['fp']) == (2, 2)
    # a: TP (rules) + FP (ML); b: TP (ML); c: TP (ML) + FP; d: nothing (no ML row)
    assert (res['combined']['tp'], res['combined']['fp']) == (3, 2)
    assert res['combined']['precision'] == pytest.approx(3 / 5)
    assert res['combined']['recall'] == pytest.approx(3 / 4)
