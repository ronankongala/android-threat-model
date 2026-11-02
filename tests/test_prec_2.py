"""Tests for P-2: exported-no-permission is reported (medium or high) only for
a component that is exported (android:exported="true", or implied by an intent
filter) and has no permission of any kind."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk as apkmod  # noqa: E402
import surface  # noqa: E402

FILTER = ('<intent-filter><action android:name="edu.ksu.cs.benign.ACT"/>'
          '<category android:name="android.intent.category.DEFAULT"/></intent-filter>')


def _manifest(tmp_path, body, perms=''):
    xml = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
           'package="edu.ksu.cs.benign">'
           '<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="27"/>%s'
           '<application>%s</application></manifest>') % (perms, body)
    path = tmp_path / 'AndroidManifest.xml'
    path.write_text(xml, encoding='utf-8')
    return apkmod.parse_manifest(str(path))


def _enp(manifest):
    return [f for f in surface.find(manifest) if f['issue'] == 'exported-no-permission']


SIGNATURE = '<permission android:name="x.SIG" android:protectionLevel="signature"/>'
NORMAL = '<permission android:name="x.NORM" android:protectionLevel="normal"/>'


@pytest.mark.parametrize('tag', ['activity', 'service', 'receiver'])
def test_signature_permission_not_flagged(tmp_path, tag):
    m = _manifest(tmp_path, '<%s android:name=".C" android:exported="true" '
                            'android:permission="x.SIG">%s</%s>' % (tag, FILTER, tag), SIGNATURE)
    assert _enp(m) == []
    assert not [f for f in surface.find(m) if f['issue'] == 'weak-permission-protection']


def test_normal_permission_is_weak_not_unprotected(tmp_path):
    m = _manifest(tmp_path, '<service android:name=".C" android:exported="true" '
                            'android:permission="x.NORM"/>', NORMAL)
    assert _enp(m) == []
    assert [f['issue'] for f in surface.find(m) if f['cwe'] == 'CWE-926'] == \
        ['weak-permission-protection']


def test_signature_provider_not_flagged(tmp_path):
    m = _manifest(tmp_path, '<provider android:name=".P" android:authorities="a.b" '
                            'android:exported="true" android:permission="x.SIG"/>', SIGNATURE)
    assert _enp(m) == []


@pytest.mark.parametrize('tag', ['activity', 'service', 'receiver'])
def test_explicit_false_with_filter_not_flagged(tmp_path, tag):
    m = _manifest(tmp_path, '<%s android:name=".C" android:exported="false">%s</%s>'
                  % (tag, FILTER, tag))
    assert _enp(m) == []


@pytest.mark.parametrize('tag', ['activity', 'service', 'receiver'])
def test_no_filter_no_attribute_not_flagged(tmp_path, tag):
    assert _enp(_manifest(tmp_path, '<%s android:name=".C"/>' % tag)) == []


def test_explicit_true_no_permission_high(tmp_path):
    hits = _enp(_manifest(tmp_path, '<service android:name=".C" android:exported="true"/>'))
    assert [f['confidence'] for f in hits] == ['high']


def test_implied_by_filter_no_permission_medium(tmp_path):
    hits = _enp(_manifest(tmp_path, '<receiver android:name=".C">%s</receiver>' % FILTER))
    assert [f['confidence'] for f in hits] == ['medium']


def test_provider_partial_permission_low(tmp_path):
    hits = _enp(_manifest(tmp_path, '<provider android:name=".P" android:authorities="a.b" '
                                    'android:exported="true" android:readPermission="x.SIG"/>',
                          SIGNATURE))
    assert [f['confidence'] for f in hits] == ['low']


def test_application_permission_protects_component(tmp_path):
    xml_body = '<service android:name=".C" android:exported="true"/>'
    m = _manifest(tmp_path, xml_body)
    m['components'][0]['permission'] = 'x.SIG'   # inherited from <application android:permission>
    assert _enp(m) == []
