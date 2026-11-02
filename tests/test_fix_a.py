"""Fix A: CWE matching in tools/evaluate.py, direct and through SECONDARY_CWE."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

import evaluate  # noqa: E402


def test_direct_match():
    assert evaluate.matching_cwes({'CWE-927', 'CWE-200'}, {'CWE-927'}) == (['CWE-927'], ['CWE-927'])


def test_secondary_match():
    strict, expanded = evaluate.matching_cwes({'CWE-829'}, {'CWE-749', 'CWE-830'})
    assert strict == []
    assert expanded == ['CWE-829->CWE-749']


def test_secondary_is_one_step_only():
    # CWE-360 maps to CWE-925, which is not chained on to CWE-926.
    assert evaluate.matching_cwes({'CWE-360'}, {'CWE-926'}) == ([], [])


def test_all_requested_mappings():
    assert evaluate.SECONDARY_CWE == {
        'CWE-829': 'CWE-749', 'CWE-925': 'CWE-926', 'CWE-360': 'CWE-925',
        'CWE-348': 'CWE-927', 'CWE-346': 'CWE-927', 'CWE-441': 'CWE-926',
    }


def test_no_match():
    assert evaluate.matching_cwes({'CWE-319'}, {'CWE-295'}) == ([], [])
