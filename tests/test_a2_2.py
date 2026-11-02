"""Tests for A2-2: exported content providers without permissions (CWE-926)
and the "Candidates to check" section for path-permission-only providers
(candidate CWE-284)."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk as apkmod  # noqa: E402
import report  # noqa: E402
import surface  # noqa: E402

PROVIDER = 'edu.ksu.cs.benign.provider.P'
BENCH = os.path.join(ROOT, 'benchmarks', 'ghera', 'ICC',
                     'InadequatePathPermission-InformationExposure-Lean')
PREFIX = '<path-permission android:pathPrefix="/user" android:readPermission="x.READ"/>'


def _manifest(tmp_path, provider_attrs, children='', target=27):
    xml = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
           'package="edu.ksu.cs.benign">'
           '<uses-sdk android:minSdkVersion="9" android:targetSdkVersion="%d"/><application>'
           '<provider android:name=".provider.P" android:authorities="edu.ksu.cs.benign.p" %s>'
           '%s</provider></application></manifest>') % (target, provider_attrs, children)
    path = tmp_path / 'AndroidManifest.xml'
    path.write_text(xml, encoding='utf-8')
    return apkmod.parse_manifest(str(path))


def _926(manifest):
    return [f for f in surface.find(manifest) if f['cwe'] == 'CWE-926']


def test_explicit_export_no_permission_high(tmp_path):
    hits = _926(_manifest(tmp_path, 'android:exported="true"'))
    assert len(hits) == 1
    f = hits[0]
    assert (f['component'], f['issue'], f['confidence']) == (
        PROVIDER, 'exported-no-permission', 'high')
    assert 'no android:permission' in f['evidence']


def test_default_export_no_permission_high(tmp_path):
    hits = _926(_manifest(tmp_path, '', target=16))
    assert [f['confidence'] for f in hits] == ['high']
    assert 'exported by default' in hits[0]['evidence']
    assert _926(_manifest(tmp_path, '', target=17)) == []


@pytest.mark.parametrize('attrs', ['android:permission="x.ALL"',
                                   'android:readPermission="x.R" android:writePermission="x.W"'])
def test_protected_provider_silent(tmp_path, attrs):
    assert _926(_manifest(tmp_path, 'android:exported="true" ' + attrs)) == []


def test_not_exported_silent(tmp_path):
    assert _926(_manifest(tmp_path, 'android:exported="false"')) == []


@pytest.mark.parametrize('attr,missing', [('android:readPermission="x.R"', 'writePermission'),
                                          ('android:writePermission="x.W"', 'readPermission')])
def test_partial_permission_low(tmp_path, attr, missing):
    # P-2 lowered this from medium: the provider has a permission of some kind.
    hits = _926(_manifest(tmp_path, 'android:exported="true" ' + attr))
    assert [f['confidence'] for f in hits] == ['low']
    assert hits[0]['evidence'].endswith('no android:' + missing)


def test_path_permission_only_one_finding_per_cwe(tmp_path):
    findings = surface.find(_manifest(tmp_path, 'android:exported="true"', PREFIX))
    keys = [(f['component'], f['cwe']) for f in findings]
    assert len(keys) == len(set(keys))
    by_cwe = {f['cwe']: f for f in findings}
    assert by_cwe['CWE-926']['confidence'] == 'high'
    assert by_cwe['CWE-284']['issue'] == 'provider-path-permission-only'
    assert 'note' in by_cwe['CWE-284'] and 'note' not in by_cwe['CWE-926']


def test_report_candidates_section(tmp_path):
    findings = surface.find(_manifest(tmp_path, 'android:exported="true"', PREFIX))
    md = report.to_markdown(findings, 'a22')
    main, _, candidates = md.partition('## Candidates to check')
    assert candidates, 'no Candidates to check section'
    assert 'provider-path-permission-only' in candidates
    assert 'provider-path-permission-only' not in main
    assert 'exported-no-permission' in main
    assert '| Note |' in candidates and 'candidate CWE-284' in candidates


def test_report_without_candidates_has_no_section(tmp_path):
    findings = surface.find(_manifest(tmp_path, 'android:exported="true"'))
    assert '## Candidates to check' not in report.to_markdown(findings, 'a22')


def _decode_or_skip(variant):
    path = os.path.join(BENCH, variant, 'app', 'build', 'outputs', 'apk', 'api27',
                        'debug', 'app-api27-debug.apk')
    if not os.path.isfile(path):
        pytest.skip('%s api27 APK not built' % variant)
    try:
        apkmod.find_java()
    except apkmod.ApkError:
        pytest.skip('java not available for apktool')
    return apkmod.decode(path)


def test_benchmark_benign_provider_high():
    hits = [f for f in _926(_decode_or_skip('Benign')) if f['component_type'] == 'provider']
    assert [f['confidence'] for f in hits] == ['high']


def test_benchmark_secure_provider_silent():
    assert [f for f in _926(_decode_or_skip('Secure')) if f['component_type'] == 'provider'] == []
