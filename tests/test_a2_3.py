"""Tests for A2-3: weak-permission-protection (CWE-926) for exported
components protected by a custom permission whose protectionLevel is normal
(or absent; confidence medium) or dangerous (confidence low)."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk as apkmod  # noqa: E402
import surface  # noqa: E402

ISSUE = 'weak-permission-protection'
BENCH = os.path.join(ROOT, 'benchmarks', 'ghera', 'Permission',
                     'WeakPermission-UnauthorizedAccess-Lean')


def _manifest(tmp_path, level_attr, comp='<provider android:name=".P" android:authorities="a.p" '
              'android:exported="true" android:permission="a.PERM"/>'):
    xml = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a">'
           '<permission android:name="a.PERM" %s/><application>%s</application></manifest>'
           % (level_attr, comp))
    path = tmp_path / 'AndroidManifest.xml'
    path.write_text(xml, encoding='utf-8')
    return apkmod.parse_manifest(str(path))


def _hits(manifest):
    return [f for f in surface.find(manifest) if f['issue'] == ISSUE]


@pytest.mark.parametrize('attr,base,confidence', [
    ('', 'normal', 'medium'),
    ('android:protectionLevel="normal"', 'normal', 'medium'),
    ('android:protectionLevel="dangerous"', 'dangerous', 'low'),
    ('android:protectionLevel="0"', 'normal', 'medium'),
    ('android:protectionLevel="0x1"', 'dangerous', 'low'),
])
def test_weak_levels_fire(tmp_path, attr, base, confidence):
    hits = _hits(_manifest(tmp_path, attr))
    assert len(hits) == 1
    f = hits[0]
    assert (f['cwe'], f['confidence'], f['component']) == ('CWE-926', confidence, 'a.P')
    assert 'protectionLevel %s' % base in f['evidence']
    assert surface.WEAK_LEVEL_NOTE[base] in f['evidence']


@pytest.mark.parametrize('level', ['signature', 'signatureOrSystem', 'signature|privileged',
                                   '2', '3', '0x2', '0x12'])
def test_strong_levels_silent(tmp_path, level):
    assert _hits(_manifest(tmp_path, 'android:protectionLevel="%s"' % level)) == []


def test_activity_with_weak_permission(tmp_path):
    comp = ('<activity android:name=".A" android:exported="true" '
            'android:permission="a.PERM"/>')
    assert [f['component'] for f in _hits(_manifest(tmp_path, '', comp))] == ['a.A']


def test_provider_read_permission(tmp_path):
    comp = ('<provider android:name=".P" android:authorities="a.p" android:exported="true" '
            'android:readPermission="a.PERM" android:writePermission="a.OTHER"/>')
    hits = _hits(_manifest(tmp_path, '', comp))
    assert len(hits) == 1 and 'android:readPermission="a.PERM"' in hits[0]['evidence']


def test_mixed_normal_and_dangerous_is_medium(tmp_path):
    xml = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a">'
           '<permission android:name="a.R" android:protectionLevel="dangerous"/>'
           '<permission android:name="a.W" android:protectionLevel="normal"/>'
           '<application><provider android:name=".P" android:authorities="a.p" '
           'android:exported="true" android:readPermission="a.R" '
           'android:writePermission="a.W"/></application></manifest>')
    path = tmp_path / 'AndroidManifest.xml'
    path.write_text(xml, encoding='utf-8')
    hits = _hits(apkmod.parse_manifest(str(path)))
    assert len(hits) == 1 and hits[0]['confidence'] == 'medium'


def test_not_exported_silent(tmp_path):
    comp = '<service android:name=".S" android:exported="false" android:permission="a.PERM"/>'
    assert _hits(_manifest(tmp_path, '', comp)) == []


def test_platform_permission_ignored(tmp_path):
    comp = ('<service android:name=".S" android:exported="true" '
            'android:permission="android.permission.BIND_JOB_SERVICE"/>')
    assert _hits(_manifest(tmp_path, '', comp)) == []


def test_protection_base():
    assert surface.protection_base(None) == 'normal'
    assert surface.protection_base('signature|privileged') == 'signature'
    assert surface.protection_base('0x11') == 'dangerous'


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


def test_benchmark_benign_fires():
    hits = _hits(_decode_or_skip('Benign'))
    assert [f['component'] for f in hits] == ['edu.ksu.cs.benign.MyContentProvider']


def test_benchmark_secure_silent():
    assert _hits(_decode_or_skip('Secure')) == []
