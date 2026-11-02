"""P1-3: secondary_cwe_ids column of data/ground-truth.csv in tools/evaluate.py."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))

import evaluate  # noqa: E402

HEADER = 'category,folder,cwe_ids,secondary_cwe_ids,model_file\n'


def _gt(tmp_path, body):
    p = tmp_path / 'gt.csv'
    p.write_text(HEADER + body, encoding='utf-8')
    return evaluate.load_ground_truth(str(p))


def test_parse_cwes():
    assert evaluate.parse_cwes('CWE-926; CWE-441 ;;') == {'CWE-926', 'CWE-441'}
    assert evaluate.parse_cwes('') == set()
    assert evaluate.parse_cwes(None) == set()


def test_load_ground_truth_reads_secondary(tmp_path):
    gt = _gt(tmp_path, 'System,A,CWE-359,CWE-200,m\nWeb,B,CWE-830,,m\n')
    assert gt['A'] == {'category': 'System', 'cwes': {'CWE-359'}, 'secondary': {'CWE-200'},
                       'components': []}  # A1-1: no vulnerable_component column in this file
    assert gt['B']['secondary'] == set()


def test_load_ground_truth_without_secondary_column(tmp_path):
    p = tmp_path / 'gt.csv'
    p.write_text('category,folder,cwe_ids\nWeb,B,CWE-830\n', encoding='utf-8')
    assert evaluate.load_ground_truth(str(p))['B']['secondary'] == set()


def test_secondary_column_match_is_expanded_only():
    strict, expanded = evaluate.matching_cwes({'CWE-200'}, {'CWE-359'}, {'CWE-200'})
    assert strict == []
    assert expanded == ['CWE-200(secondary)']


def test_secondary_cwe_dict_label_wins():
    # A finding matched through SECONDARY_CWE keeps the 'found->gt' label even
    # when the column also lists it.
    assert evaluate.matching_cwes({'CWE-925'}, {'CWE-926'}, {'CWE-925'}) == ([], ['CWE-925->CWE-926'])


def test_secondary_needs_a_finding():
    assert evaluate.matching_cwes({'CWE-319'}, {'CWE-359'}, {'CWE-200'}) == ([], [])


def test_score_row_strict_ignores_secondary():
    entry = {'category': 'System', 'cwes': {'CWE-359'}, 'secondary': {'CWE-200'}}
    row, matched = evaluate.score_row('A', entry, [{'cwe': 'CWE-200'}], [])
    assert (row['true_positive'], row['strict_true_positive'], row['false_positive']) == (1, 0, 0)
    assert matched == ['CWE-200(secondary)']


def test_score_row_missing_reports():
    entry = {'category': 'Web', 'cwes': {'CWE-830'}, 'secondary': set()}
    row, _ = evaluate.score_row('B', entry, None, None)
    assert row['benign_findings'] == '' and row['secure_findings'] == ''
    assert row['true_positive'] == 0 and row['false_positive'] == 0


def test_real_column_contains_fix_a_reverse_mapping():
    # Every SECONDARY_CWE key that maps to a cwe_ids entry is listed in the
    # column, so reading the column cannot change a Fix A result.
    for bench, g in evaluate.load_ground_truth().items():
        derived = {c for c, t in evaluate.SECONDARY_CWE.items() if t in g['cwes']} - g['cwes']
        assert derived <= g['secondary'], bench


def test_real_column_p1_3_additions():
    gt = evaluate.load_ground_truth()
    extra = {}
    for bench, g in gt.items():
        derived = {c for c, t in evaluate.SECONDARY_CWE.items() if t in g['cwes']} - g['cwes']
        if g['secondary'] - derived:
            extra[bench] = g['secondary'] - derived
    assert extra == {
        'ClipboardUse-InformationExposure-Lean': {'CWE-200'},
        'WebViewAllowFileAccess-UnauthorizedFileAccess-Lean': {'CWE-829'},
    }


def test_rescore_reads_reports_and_drops_dynamic(tmp_path, capsys):
    d = tmp_path / 'A'
    (d / 'Benign').mkdir(parents=True)
    (d / 'Secure').mkdir()
    (d / 'Benign' / evaluate.REPORT).write_text(json.dumps([
        {'cwe': 'CWE-926', 'issue': 'dynamic-receiver-accepts-external'},
        {'cwe': 'CWE-200', 'issue': 'clipboard_sensitive'}]))
    (d / 'Secure' / evaluate.REPORT).write_text(json.dumps([
        {'cwe': 'CWE-926', 'issue': 'dynamic-receiver-accepts-external'}]))
    gt = {'A': {'category': 'System', 'cwes': {'CWE-926'}, 'secondary': {'CWE-200'}}}
    static = evaluate.rescore(['A', 'missing'], gt, dynamic=False, tmp=str(tmp_path))
    assert len(static) == 1
    assert static[0]['benign_findings'] == 1 and static[0]['secure_findings'] == 0
    assert (static[0]['true_positive'], static[0]['strict_true_positive']) == (1, 0)
    dyn = evaluate.rescore(['A'], gt, dynamic=True, tmp=str(tmp_path))[0]
    assert (dyn['benign_findings'], dyn['strict_true_positive'], dyn['false_positive']) == (2, 1, 1)
