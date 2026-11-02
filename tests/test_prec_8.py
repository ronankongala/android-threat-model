"""P-8: differential mode (--diff-mode) scores only the findings that differ
between the Benign and the Secure APK."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))

import evaluate  # noqa: E402


def f(component, cwe, issue):
    return {'component': component, 'component_type': 'class', 'issue': issue, 'cwe': cwe,
            'confidence': 'high'}


GT = {'category': 'Crypto', 'cwes': {'CWE-327', 'CWE-926'}, 'secondary': set(),
      'components': ['edu.ksu.cs.benign.NewPasswordActivity']}
EXPORT_B = f('edu.ksu.cs.benign.NewPasswordActivity', 'CWE-926', 'exported-no-permission')
ECB_B = f('edu.ksu.cs.benign.NewPasswordActivity', 'CWE-327', 'ecb_mode')


def test_shared_finding_dropped_on_both_sides():
    b, s = evaluate.diff_findings([EXPORT_B, ECB_B], [dict(EXPORT_B)])
    assert b == [ECB_B] and s == []


def test_package_ignored_when_matching():
    secure = f('edu.ksu.cs.secure.NewPasswordActivity', 'CWE-926', 'exported-no-permission')
    b, s = evaluate.diff_findings([EXPORT_B], [secure])
    assert b == [] and s == []


def test_secure_only_finding_kept():
    new = f('edu.ksu.cs.benign.NewPasswordActivity', 'CWE-926', 'implicit-intent')
    b, s = evaluate.diff_findings([EXPORT_B], [EXPORT_B, new])
    assert b == [] and s == [new]


def test_missing_secure_left_unchanged():
    assert evaluate.diff_findings([EXPORT_B], None) == ([EXPORT_B], None)


def test_score_row_standard_vs_diff():
    # Standard mode: the shared export finding makes the benchmark a false positive.
    row, _ = evaluate.score_row('B', GT, [EXPORT_B, ECB_B], [dict(EXPORT_B)])
    assert (row['true_positive'], row['false_positive']) == (1, 1)
    # Differential: only ecb_mode is left on Benign, nothing on Secure.
    row, matched = evaluate.score_row('B', GT, [EXPORT_B, ECB_B], [dict(EXPORT_B)], diff=True)
    assert (row['true_positive'], row['false_positive']) == (1, 0)
    assert matched == ['CWE-327']
    assert (row['benign_findings'], row['secure_findings']) == (1, 0)


def test_diff_can_lose_a_true_positive():
    # The fix did not remove the only matching finding: no true positive in diff mode.
    row, _ = evaluate.score_row('B', GT, [EXPORT_B], [dict(EXPORT_B)], diff=True)
    assert row['true_positive'] == 0


def test_rescore_accepts_diff():
    assert evaluate.rescore([], {}, diff=True) == []
