"""Empirical confidence calibration (P-9).

Each finding's rule is its 'issue' (the code pattern name for smali findings,
'taint-flow' for taint findings, the manifest issue otherwise). The per-rule
precision comes from the Ghera evaluation: data/rule-precision.json, written
by `python tools/evaluate.py --rescore --write-rule-precision`, maps

    {"rules": {rule: {"tp": int, "fp": int, "precision": float or null}}, ...}

where tp counts the benchmarks whose Benign APK has a finding of the rule with a
ground-truth CWE, and fp the benchmarks whose Secure APK has a finding of the
rule that counts as a false positive (the A1-1 definition in tools/evaluate.py).
precision is tp / (tp + fp), or null when the rule has neither.

calibrate() multiplies the base confidence of each finding (BASE_CONFIDENCE:
high 0.9, medium 0.6, low 0.3) by its rule's precision and keeps only findings
whose calibrated confidence is above THRESHOLD (0.3). A rule with no precision
(not in the file, or null) is not scaled. Since low is 0.3 before scaling,
every low finding is dropped. Kept findings get two extra keys,
'calibrated_confidence' and 'rule_precision'.

The scores are measured on the same 53 benchmarks the tool is evaluated on; to
score the evaluation itself without that leak, tools/evaluate.py --calibrate
uses leave-one-out precision (each benchmark scored with counts from the
others).
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PATH = os.path.join(ROOT, 'data', 'rule-precision.json')
BASE_CONFIDENCE = {'high': 0.9, 'medium': 0.6, 'low': 0.3}
THRESHOLD = 0.3


def rule_of(finding):
    return finding.get('issue')


def precision(tp, fp):
    return tp / (tp + fp) if tp + fp else None


def load(path=None):
    """{rule: precision or None} from a rule-precision JSON file."""
    with open(path or DEFAULT_PATH, encoding='utf-8') as f:
        data = json.load(f)
    return {rule: v.get('precision') for rule, v in data.get('rules', {}).items()}


def calibrated(finding, scores):
    """(calibrated confidence, rule precision or None) for one finding."""
    base = BASE_CONFIDENCE.get(finding.get('confidence'), BASE_CONFIDENCE['medium'])
    p = scores.get(rule_of(finding))
    return (base * p if p is not None else base), p


def calibrate(findings, scores, threshold=THRESHOLD):
    """Findings whose calibrated confidence is above threshold, each a copy with
    'calibrated_confidence' and 'rule_precision' added."""
    kept = []
    for f in findings or []:
        value, p = calibrated(f, scores)
        if value > threshold + 1e-9:
            g = dict(f)
            g['calibrated_confidence'] = round(value, 3)
            g['rule_precision'] = None if p is None else round(p, 3)
            kept.append(g)
    return kept
