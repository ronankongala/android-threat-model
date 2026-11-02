"""A1-1: a Secure finding is a false positive only with an exact cwe_ids CWE on the
benchmark's vulnerable component; false_positive_any keeps the old definition."""
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))

import evaluate  # noqa: E402

B = 'edu.ksu.cs.benign.'


def finding(component, cwe, issue='x'):
    return {'component': component, 'component_type': 'class', 'issue': issue, 'cwe': cwe}


def entry(cwes, components, secondary=()):
    return {'category': 'ICC', 'cwes': set(cwes), 'secondary': set(secondary),
            'components': list(components)}


# component_matches

def test_same_class_matches():
    assert evaluate.component_matches(B + 'MyReceiver', [B + 'MyReceiver'])


def test_inner_class_matches_outer():
    assert evaluate.component_matches(B + 'MainActivity$1', [B + 'MainActivity'])
    assert evaluate.component_matches(B + 'MainActivity$Inner$2', [B + 'MainActivity'])


def test_other_class_does_not_match():
    assert not evaluate.component_matches(B + 'MainActivity', [B + 'MyReceiver'])
    # a name prefix is not an inner class
    assert not evaluate.component_matches(B + 'MainActivity2', [B + 'MainActivity'])
    # different package, same simple name
    assert not evaluate.component_matches('edu.ksu.cs.secure.MainActivity', [B + 'MainActivity'])


def test_outer_does_not_match_listed_inner_class_only_by_prefix():
    # a listed nested package path (Util.Encrypt) is not matched by its package (Util)
    assert not evaluate.component_matches(B + 'Util', [B + 'Util.Encrypt'])
    assert evaluate.component_matches(B + 'Util.Encrypt', [B + 'Util.Encrypt'])


def test_simple_name_compares_simple_names():
    assert evaluate.component_matches('com.android.mms.transaction.SmsReceiver', ['SmsReceiver'])
    assert evaluate.component_matches('a.b.SmsReceiver$1', ['SmsReceiver'])
    assert not evaluate.component_matches('a.b.MmsReceiver', ['SmsReceiver'])


def test_any_listed_component_matches():
    listed = [B + 'MyTrustManager', B + 'MyIntentService']
    assert evaluate.component_matches(B + 'MyIntentService$1', listed)
    assert evaluate.component_matches(B + 'MyTrustManager', listed)


def test_blank_or_application_matches_everything():
    for vulnerable in ([], None, ['(application)']):
        assert evaluate.component_matches(B + 'Anything', vulnerable)
        assert evaluate.component_matches('(application)', vulnerable)


def test_application_finding_does_not_match_named_class():
    assert not evaluate.component_matches('(application)', [B + 'HttpIntentService'])


def test_parse_components():
    assert evaluate.parse_components(' a.B ; c.D;; ') == ['a.B', 'c.D']
    assert evaluate.parse_components('') == []
    assert evaluate.parse_components(None) == []


# false positive rule

def test_launcher_export_on_other_component_is_not_fp():
    e = entry({'CWE-926'}, [B + 'MyReceiver'])
    secure = [finding(B + 'MainActivity', 'CWE-926', 'exported-no-permission')]
    row, _ = evaluate.score_row('X', e, [], secure)
    assert row['false_positive'] == 0
    assert row['false_positive_any'] == 1


def test_exact_cwe_on_vulnerable_component_is_fp():
    e = entry({'CWE-926'}, [B + 'MyReceiver'])
    row, _ = evaluate.score_row('X', e, [], [finding(B + 'MyReceiver', 'CWE-926')])
    assert (row['false_positive'], row['false_positive_any']) == (1, 1)


def test_inner_class_finding_on_vulnerable_component_is_fp():
    e = entry({'CWE-927'}, [B + 'MainActivity'])
    row, _ = evaluate.score_row('X', e, [], [finding(B + 'MainActivity$1', 'CWE-927')])
    assert row['false_positive'] == 1


def test_secondary_cwe_on_vulnerable_component_is_not_fp():
    # CWE-925 maps to CWE-926 through SECONDARY_CWE and is in secondary_cwe_ids,
    # but only an exact cwe_ids CWE makes a false positive
    e = entry({'CWE-926'}, [B + 'MyReceiver'], secondary={'CWE-925'})
    row, _ = evaluate.score_row('X', e, [], [finding(B + 'MyReceiver', 'CWE-925')])
    assert (row['false_positive'], row['false_positive_any']) == (0, 1)


def test_cwe_and_component_must_hold_for_the_same_finding():
    e = entry({'CWE-926'}, [B + 'MyReceiver'])
    secure = [finding(B + 'MyReceiver', 'CWE-532'), finding(B + 'MainActivity', 'CWE-926')]
    row, _ = evaluate.score_row('X', e, [], secure)
    assert row['false_positive'] == 0


def test_application_column_uses_cwe_alone():
    e = entry({'CWE-1021'}, ['(application)'])
    row, _ = evaluate.score_row('X', e, [], [finding('edu.ksu.cs.benign', 'CWE-1021')])
    assert row['false_positive'] == 1
    row, _ = evaluate.score_row('X', e, [], [finding('edu.ksu.cs.benign', 'CWE-926')])
    assert row['false_positive'] == 0


def test_missing_components_key_uses_cwe_alone():
    e = {'category': 'ICC', 'cwes': {'CWE-926'}, 'secondary': set()}
    row, _ = evaluate.score_row('X', e, [], [{'cwe': 'CWE-926'}])
    assert row['false_positive'] == 1


def test_no_secure_findings_or_missing_report():
    e = entry({'CWE-926'}, [B + 'MyReceiver'])
    for secure in ([], None):
        row, _ = evaluate.score_row('X', e, [], secure)
        assert (row['false_positive'], row['false_positive_any']) == (0, 0)


def test_true_positive_unchanged_by_component():
    # TP looks at Benign CWEs only; the component plays no part
    e = entry({'CWE-926'}, [B + 'MyReceiver'])
    row, _ = evaluate.score_row('X', e, [finding(B + 'Other', 'CWE-926')], [])
    assert (row['true_positive'], row['strict_true_positive']) == (1, 1)


def test_two_app_secure_findings_follow_the_rule():
    e = entry({'CWE-1021'}, [B + 'ImageEditor'])
    hijack = finding('edu.ksu.cs.benign', 'CWE-1021', 'dynamic-task-hijack')
    row, _ = evaluate.score_row('X', e, [], [], {'Benign': [], 'Secure': [hijack]})
    assert (row['false_positive'], row['false_positive_any']) == (0, 1)


# summary, columns, ground truth, rescore

def test_columns_end_with_false_positive_any():
    assert evaluate.COLUMNS[-1] == 'false_positive_any'
    assert evaluate.COLUMNS.index('false_positive') == 5


def test_summary_prints_new_and_legacy_precision():
    rows = [
        {'true_positive': 1, 'strict_true_positive': 1, 'false_positive': 0, 'false_positive_any': 1},
        {'true_positive': 1, 'strict_true_positive': 0, 'false_positive': 1, 'false_positive_any': 1},
        {'true_positive': 0, 'strict_true_positive': 0, 'false_positive': 0, 'false_positive_any': 1},
        {'true_positive': 0, 'strict_true_positive': 0, 'false_positive': 0, 'false_positive_any': 0},
    ]
    text = '\n'.join(evaluate.summary(rows))
    assert '2 true positives, 1 false positives' in text
    assert '3 with any Secure finding' in text
    assert 'Precision 0.67, recall 0.50' in text
    assert 'precision 0.50, recall 0.25' in text  # strict: 1 / (1 + 1)
    assert 'Legacy precision (false positive = any Secure finding): 0.40, strict 0.25' in text


def test_ground_truth_has_vulnerable_component_for_every_row():
    with open(evaluate.GROUND_TRUTH, encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames[-1] == 'vulnerable_component'
        rows = list(reader)
    assert len(rows) == 57
    gt = evaluate.load_ground_truth()
    assert gt['UnprotectedBroadcastRecv-PrivEscalation-Lean']['components'] == [B + 'MyReceiver']
    assert gt['TaskAffinity-LauncherActivity-PhishingAttack-Lean']['components'] == ['(application)']
    assert gt['EmptyPendingIntent-PrivEscalation-Lean']['components'] == [
        B + 'MainActivity', 'edu.cs.ksu.benign.MainActivity']


def test_rescore_writes_both_columns(tmp_path):
    d = tmp_path / 'A'
    (d / 'Benign').mkdir(parents=True)
    (d / 'Secure').mkdir(parents=True)
    (d / 'Benign' / evaluate.REPORT).write_text(json.dumps([finding(B + 'MyReceiver', 'CWE-926')]))
    (d / 'Secure' / evaluate.REPORT).write_text(json.dumps([
        finding(B + 'MainActivity', 'CWE-926', 'exported-no-permission')]))
    gt = {'A': entry({'CWE-926'}, [B + 'MyReceiver'])}
    rows = evaluate.rescore(['A'], gt, tmp=str(tmp_path))
    assert (rows[0]['true_positive'], rows[0]['false_positive'], rows[0]['false_positive_any']) == (1, 0, 1)
    out = tmp_path / 'out.csv'
    evaluate.write_rows(rows, str(out))
    row, = list(csv.DictReader(open(out, encoding='utf-8')))
    assert (row['false_positive'], row['false_positive_any']) == ('0', '1')
