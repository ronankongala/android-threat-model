"""P-9: empirical confidence calibration (src/calibration.py) and the
evaluator's per-rule counts and leave-one-out scoring."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))
sys.path.insert(0, os.path.join(ROOT, 'tools'))

import calibration  # noqa: E402
import evaluate  # noqa: E402

B = 'edu.ksu.cs.benign.'


def f(issue, cwe, conf='high', component=B + 'Main'):
    return {'component': component, 'component_type': 'class', 'issue': issue, 'cwe': cwe,
            'confidence': conf}


def entry(cwes, components=(B + 'Main',)):
    return {'category': 'ICC', 'cwes': set(cwes), 'secondary': set(), 'components': list(components)}


# calibration.py

@pytest.mark.parametrize('conf,p,kept', [
    ('high', 1.0, True), ('high', 0.34, True), ('high', 0.33, False),
    ('medium', 0.51, True), ('medium', 0.5, False),
    ('low', 1.0, False),
])
def test_threshold(conf, p, kept):
    out = calibration.calibrate([f('r', 'CWE-1', conf)], {'r': p})
    assert bool(out) == kept


def test_unscored_rule_keeps_base():
    out = calibration.calibrate([f('new', 'CWE-1', 'medium')], {'r': 0.1})
    assert out[0]['calibrated_confidence'] == 0.6
    assert out[0]['rule_precision'] is None


def test_kept_finding_annotated_and_input_unchanged():
    src = f('r', 'CWE-1', 'high')
    out = calibration.calibrate([src], {'r': 0.5})
    assert out[0]['calibrated_confidence'] == 0.45 and out[0]['rule_precision'] == 0.5
    assert 'calibrated_confidence' not in src


def test_load(tmp_path):
    path = tmp_path / 'rp.json'
    path.write_text(json.dumps({'rules': {'a': {'tp': 1, 'fp': 1, 'precision': 0.5},
                                          'b': {'tp': 0, 'fp': 0, 'precision': None}}}))
    assert calibration.load(str(path)) == {'a': 0.5, 'b': None}


# evaluator counts

def test_rule_hits():
    gt = entry({'CWE-926'})
    benign = [f('exported-no-permission', 'CWE-926'), f('cleartext-http', 'CWE-319')]
    secure = [f('exported-no-permission', 'CWE-926', 'medium'),
              f('implicit-intent', 'CWE-926', 'low')]
    assert evaluate.rule_hits(gt, benign, secure) == {'exported-no-permission': [1, 1]}


def test_rule_totals_leave_one_out():
    per = {'A': {'r': [1, 0]}, 'B': {'r': [1, 1]}, 'C': {'r': [0, 1], 's': [1, 0]}}
    assert evaluate.rule_totals(per) == {'r': (2, 2), 's': (1, 0)}
    assert evaluate.rule_totals(per, exclude='B') == {'r': (1, 1), 's': (1, 0)}
    assert evaluate.rule_scores(evaluate.rule_totals(per, exclude='C')) == {'r': 2 / 3}


def test_write_rule_precision(tmp_path):
    path = tmp_path / 'rp.json'
    evaluate.write_rule_precision({'A': {'r': [1, 0]}, 'B': {'r': [0, 1], 'q': [0, 0]}}, str(path))
    data = json.loads(path.read_text())
    assert data['rules']['r'] == {'tp': 1, 'fp': 1, 'precision': 0.5}
    assert data['rules']['q']['precision'] is None


def _reports(tmp, bench, benign, secure):
    for variant, findings in (('Benign', benign), ('Secure', secure)):
        d = tmp / bench / variant
        d.mkdir(parents=True)
        (d / evaluate.REPORT).write_text(json.dumps(findings))


def test_rescore_calibrate_leave_one_out(tmp_path):
    # Rule "bad" is a false positive on A and B; scoring C with the counts of
    # A and B gives it precision 0 there, so C's Secure finding is dropped.
    gt = {b: entry({'CWE-926'}) for b in 'ABC'}
    for b in 'AB':
        _reports(tmp_path, b, [f('good', 'CWE-926')], [f('bad', 'CWE-926')])
    _reports(tmp_path, 'C', [f('good', 'CWE-926')], [f('bad', 'CWE-926')])
    plain = evaluate.rescore(list('ABC'), gt, tmp=str(tmp_path))
    assert [r['false_positive'] for r in plain] == [1, 1, 1]
    cal = evaluate.rescore(list('ABC'), gt, tmp=str(tmp_path), calibrate=True)
    assert [r['false_positive'] for r in cal] == [0, 0, 0]
    assert [r['true_positive'] for r in cal] == [1, 1, 1]


def test_rescore_calibrate_drops_low_true_positive(tmp_path):
    gt = {'A': entry({'CWE-1021'})}
    _reports(tmp_path, 'A', [f('default-task-affinity', 'CWE-1021', 'low')], [])
    assert evaluate.rescore(['A'], gt, tmp=str(tmp_path))[0]['true_positive'] == 1
    assert evaluate.rescore(['A'], gt, tmp=str(tmp_path), calibrate=True)[0]['true_positive'] == 0


def test_flags_need_rescore():
    with pytest.raises(SystemExit):
        evaluate.main(['--calibrate'])
