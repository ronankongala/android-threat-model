"""Tests for P2-5: provider-path-permission-only (candidate CWE-284, medium)
for exported content providers protected only by <path-permission> children,
using synthetic manifests and, when built, the InadequatePathPermission
benchmark APKs."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk as apkmod  # noqa: E402
import report  # noqa: E402
import surface  # noqa: E402

ISSUE = 'provider-path-permission-only'
BENCH = os.path.join(ROOT, 'benchmarks', 'ghera', 'ICC',
                     'InadequatePathPermission-InformationExposure-Lean')


def _manifest(tmp_path, provider_attrs, children='', target=27, uses_sdk=True):
    sdk = ('<uses-sdk android:minSdkVersion="19" android:targetSdkVersion="%d"/>' % target
           if uses_sdk else '')
    xml = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
           'package="edu.ksu.cs.benign">%s<application>'
           '<provider android:name=".provider.P" android:authorities="edu.ksu.cs.benign.p" %s>'
           '%s</provider></application></manifest>') % (sdk, provider_attrs, children)
    path = tmp_path / 'AndroidManifest.xml'
    path.write_text(xml, encoding='utf-8')
    return apkmod.parse_manifest(str(path))


def _hits(manifest):
    return [f for f in surface.find(manifest) if f['issue'] == ISSUE]


PREFIX = '<path-permission android:pathPrefix="/user" android:readPermission="x.READ"/>'
EXACT = '<path-permission android:path="/user" android:readPermission="x.READ"/>'


def test_path_permission_only_fires(tmp_path):
    hits = _hits(_manifest(tmp_path, 'android:exported="true"', PREFIX))
    assert len(hits) == 1
    f = hits[0]
    assert f['cwe'] == 'CWE-284'
    assert f['confidence'] == 'medium'
    assert f['component'] == 'edu.ksu.cs.benign.provider.P'
    assert 'candidate CWE-284' in f['note'] and 'DISCOURAGED' in f['note']
    assert 'android:pathPrefix="/user"' in f['evidence']
    assert 'other paths are unprotected' in f['evidence']


def test_provider_permission_suppresses(tmp_path):
    m = _manifest(tmp_path, 'android:exported="true" android:permission="x.ALL"', EXACT)
    assert _hits(m) == []


def test_read_and_write_permission_suppresses(tmp_path):
    m = _manifest(tmp_path, 'android:exported="true" android:readPermission="x.R" '
                  'android:writePermission="x.W"', EXACT)
    assert _hits(m) == []


def test_exact_path_with_partial_provider_permission(tmp_path):
    # readPermission only: writes are open; android:path leaves subpaths open.
    m = _manifest(tmp_path, 'android:exported="true" android:readPermission="x.R"', EXACT)
    hits = _hits(m)
    assert len(hits) == 1
    assert 'android:path (exact match)' in hits[0]['evidence']
    assert 'other paths are unprotected' not in hits[0]['evidence']


def test_prefix_with_partial_provider_permission_silent(tmp_path):
    m = _manifest(tmp_path, 'android:exported="true" android:readPermission="x.R"', PREFIX)
    assert _hits(m) == []


def test_exact_path_reported(tmp_path):
    hits = _hits(_manifest(tmp_path, 'android:exported="true"', EXACT))
    assert len(hits) == 1
    assert 'subpaths unprotected: /user' in hits[0]['evidence']


def test_not_exported(tmp_path):
    assert _hits(_manifest(tmp_path, 'android:exported="false"', PREFIX)) == []


def test_no_path_permissions(tmp_path):
    assert _hits(_manifest(tmp_path, 'android:exported="true"')) == []


def test_default_export_rule(tmp_path):
    # No android:exported: exported by default only when targetSdkVersion < 17.
    assert len(_hits(_manifest(tmp_path, '', PREFIX, target=16))) == 1
    assert _hits(_manifest(tmp_path, '', PREFIX, target=17)) == []


def test_report_renders_extra_key(tmp_path):
    findings = _hits(_manifest(tmp_path, 'android:exported="true"', PREFIX))
    md = report.to_markdown(findings, 'p25')
    assert 'provider-path-permission-only' in md and 'CWE-284' in md
    json_path, _ = report.write(findings, 'p25', str(tmp_path / 'out'))
    assert os.path.exists(json_path)


def _apk_path(variant):
    return os.path.join(BENCH, variant, 'app', 'build', 'outputs', 'apk', 'api27',
                        'debug', 'app-api27-debug.apk')


def _decode_or_skip(variant):
    path = _apk_path(variant)
    if not os.path.isfile(path):
        pytest.skip('%s api27 APK not built' % variant)
    try:
        apkmod.find_java()
    except apkmod.ApkError:
        pytest.skip('java not available for apktool')
    return apkmod.decode(path)


def test_benchmark_benign_fires():
    assert len(_hits(_decode_or_skip('Benign'))) == 1


def test_benchmark_secure_silent():
    assert _hits(_decode_or_skip('Secure')) == []
