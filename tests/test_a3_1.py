"""Tests for A3-1: sticky-broadcast-intercepted (CWE-927, high) in two-APK
mode, when a second APK receives the action of a sticky broadcast the
analyzed app sends."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk as apkmod  # noqa: E402
import code_analyzer  # noqa: E402
import surface  # noqa: E402

ISSUE = 'sticky-broadcast-intercepted'
ACTION = 'santos.cs.ksu.edu.benign.MyReceiver'
BENCH = os.path.join(ROOT, 'benchmarks', 'ghera', 'ICC', 'StickyBroadcast-DataInjection-Lean')
STICKY_CODE = [{'pattern': 'sticky_broadcast'}]
SENT = {'sticky': [{'action': ACTION, 'component': 'a.Main', 'file': 'smali/a/Main.smali',
                    'line': 9, 'evidence': 'invoke-virtual ... sendStickyBroadcast'}],
        'receivers': {}}


def _fake(monkeypatch, receivers):
    def actions(decoded_dir):
        return SENT if decoded_dir == 'first' else {'sticky': [], 'receivers': receivers}
    monkeypatch.setattr(code_analyzer, 'broadcast_actions', actions)


def test_matching_receiver_fires(monkeypatch):
    _fake(monkeypatch, {ACTION: ['registerReceiver']})
    hits = surface._sticky_intercepted('first', {'decoded_dir': 'second', 'package': 'm'},
                                       STICKY_CODE)
    assert len(hits) == 1
    f = hits[0]
    assert (f['component'], f['cwe'], f['confidence'], f['issue']) == (
        'a.Main', 'CWE-927', 'high', ISSUE)
    assert ACTION in f['evidence'] and 'registerReceiver' in f['evidence']
    assert f['line'] == 9


def test_other_action_silent(monkeypatch):
    _fake(monkeypatch, {'other.ACTION': ['manifest <receiver> m.R']})
    assert surface._sticky_intercepted('first', {'decoded_dir': 'second'}, STICKY_CODE) == []


def test_no_sticky_code_finding_skips_scan(monkeypatch):
    def boom(_):
        raise AssertionError('scan should not run')
    monkeypatch.setattr(code_analyzer, 'broadcast_actions', boom)
    assert surface._sticky_intercepted('first', {'decoded_dir': 'second'}, []) == []


def test_without_second_apk_unchanged():
    manifest = {'components': []}
    assert surface.find(manifest) == surface.find(manifest, second=None)


def _decode_or_skip(variant, tmp_path):
    path = os.path.join(BENCH, variant, 'app', 'build', 'outputs', 'apk', 'api27',
                        'debug', 'app-api27-debug.apk')
    if not os.path.isfile(path):
        pytest.skip('%s api27 APK not built' % variant)
    try:
        apkmod.find_java()
    except apkmod.ApkError:
        pytest.skip('java not available for apktool')
    work = tmp_path / variant
    work.mkdir()
    return apkmod.decode(path, str(work))


@pytest.fixture(scope='module')
def decoded(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('sticky')
    return {v: _decode_or_skip(v, tmp) for v in ('Benign', 'Secure', 'Malicious')}


def test_benchmark_actions(decoded):
    sent = code_analyzer.broadcast_actions(decoded['Benign']['decoded_dir'])['sticky']
    assert [s['action'] for s in sent] == [ACTION]
    received = code_analyzer.broadcast_actions(decoded['Malicious']['decoded_dir'])['receivers']
    assert ACTION in received


def test_benchmark_benign_fires(decoded):
    hits = [f for f in surface.find(decoded['Benign'], second=decoded['Malicious'])
            if f['issue'] == ISSUE]
    assert [f['component'] for f in hits] == ['edu.ksu.cs.benign.MainActivity']


def test_benchmark_secure_silent(decoded):
    assert [f for f in surface.find(decoded['Secure'], second=decoded['Malicious'])
            if f['issue'] == ISSUE] == []
