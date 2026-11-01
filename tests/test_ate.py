"""Tests for the android-threat-engine tool.

Fixture: the api27 debug APK of the Benign app of
ICC/DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean, built during the smoke
test (docs/notes/SETUP_LOG.md). The tests are skipped if that APK is missing.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk  # noqa: E402
import report  # noqa: E402
import surface  # noqa: E402

FIXTURE_APK = os.path.join(
    ROOT, 'benchmarks', 'ghera', 'ICC', 'DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean',
    'Benign', 'app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')


@pytest.fixture(scope='module')
def decoded():
    if not os.path.exists(FIXTURE_APK):
        pytest.skip('fixture APK not built: %s' % FIXTURE_APK)
    return apk.decode(FIXTURE_APK)


@pytest.fixture(scope='module')
def findings(decoded):
    return surface.find(decoded)


def test_apk_returns_dict_with_components(decoded):
    assert isinstance(decoded, dict)
    for key in ('package', 'permissions', 'declared_permissions', 'components'):
        assert key in decoded
    assert decoded['package'] == 'edu.ksu.cs.benign'
    assert decoded['components'], 'components list is empty'
    for comp in decoded['components']:
        for key in ('name', 'type', 'exported', 'intent_filters', 'permission'):
            assert key in comp


def test_surface_finds_exported_no_permission(findings):
    issues = [f for f in findings if f['issue'] == 'exported-no-permission']
    assert issues
    for f in findings:
        assert f['issue'] in surface.ISSUES
        assert f['cwe'] == surface.CWE[f['issue']]
        assert f['confidence'] in surface.CONFIDENCE


def test_report_writes_both_files(findings, tmp_path):
    json_path, md_path = report.write(findings, 'fixture', str(tmp_path))
    assert os.path.basename(json_path) == 'fixture-report.json'
    assert os.path.basename(md_path) == 'fixture-report.md'
    with open(json_path, encoding='utf-8') as f:
        assert json.load(f) == findings
    with open(md_path, encoding='utf-8') as f:
        md = f.read()
    assert '| Component | Type | Issue | CWE | Confidence |' in md
    assert 'exported-no-permission' in md
