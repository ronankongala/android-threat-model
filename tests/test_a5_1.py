"""A5-1: feature extraction of the ML layer (src/ml_layer.py) on a synthetic
manifest dict and decoded folder, plus a cross-validation smoke test."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import ml_layer  # noqa: E402


def _smali(decoded, rel, body):
    path = os.path.join(decoded, *rel.split('/'))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write('.class public L%s;\n.super Ljava/lang/Object;\n%s\n' % (rel[rel.index('/') + 1:-6], body))


def _comp(name, ctype='activity', exported=False):
    return {'name': name, 'type': ctype, 'exported': exported, 'intent_filters': []}


@pytest.fixture
def app(tmp_path):
    decoded = str(tmp_path / 'decoded')
    # Main's inner class opens a URL connection; Store uses SQLite and files.
    _smali(decoded, 'smali/com/ex/Main.smali', 'invoke-virtual {v0}, Lcom/ex/Main;->foo()V')
    _smali(decoded, 'smali/com/ex/Main$1.smali',
           'invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;')
    _smali(decoded, 'smali/com/ex/Store.smali',
           'invoke-virtual {v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V\n'
           'invoke-virtual {p0, v1, v2}, Lcom/ex/Store;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;')
    _smali(decoded, 'smali_classes2/com/ex/Recv.smali', 'const-string v0, "hello"')
    # Library code is skipped: neither the cipher nor the SMS call counts.
    _smali(decoded, 'smali/android/support/Lib.smali',
           'invoke-static {}, Ljavax/crypto/Cipher;->getInstance()V\n'
           'invoke-static {}, Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;')
    manifest = {
        'package': 'com.ex',
        'permissions': ['android.permission.INTERNET', 'android.permission.READ_SMS',
                        'android.permission.WRITE_EXTERNAL_STORAGE', 'com.other.permission.X'],
        'declared_permissions': [{'name': 'com.ex.permission.A', 'protectionLevel': 'signature'}],
        'components': [_comp('com.ex.Main', exported=True), _comp('com.ex.Store', 'provider'),
                       _comp('com.ex.Recv', 'receiver', exported=True)],
    }
    return manifest, decoded


def test_features(app):
    manifest, decoded = app
    f = ml_layer.features(manifest, decoded)
    assert list(f) == ml_layer.FEATURES
    assert f == {'exported_components': 2, 'permissions': 4, 'dangerous_permissions': 2,
                 'custom_permissions': 1, 'internet_components': 1, 'has_webview': 0,
                 'has_sqlite': 1, 'has_crypto': 0, 'has_file_storage': 1, 'has_sms': 0}


def test_decoded_dir_from_manifest_dict(app):
    manifest, decoded = app
    manifest['decoded_dir'] = decoded
    assert ml_layer.features(manifest)['has_sqlite'] == 1


def test_internet_components_need_internet_permission(app):
    manifest, decoded = app
    manifest['permissions'].remove('android.permission.INTERNET')
    assert ml_layer.features(manifest, decoded)['internet_components'] == 0


def test_code_patterns(tmp_path):
    decoded = str(tmp_path / 'decoded')
    _smali(decoded, 'smali/com/ex/A.smali',
           'new-instance v0, Landroid/webkit/WebView;\n'
           'invoke-static {}, Ljava/security/MessageDigest;->getInstance()V\n'
           'invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;\n'
           'invoke-static {}, Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;')
    manifest = {'permissions': ['android.permission.INTERNET'], 'declared_permissions': [],
                'components': [_comp('com.ex.A')]}
    f = ml_layer.features(manifest, decoded)
    assert f['has_webview'] == f['has_crypto'] == f['has_file_storage'] == f['has_sms'] == 1
    assert f['internet_components'] == 1   # WebView counts as a network API
    assert f['has_sqlite'] == 0


def test_no_decoded_dir_gives_manifest_features_only():
    manifest = {'permissions': ['android.permission.CAMERA'], 'declared_permissions': [],
                'components': [_comp('a.B', exported=True)]}
    f = ml_layer.features(manifest)
    assert f['exported_components'] == 1 and f['dangerous_permissions'] == 1
    assert sum(f[k] for k in ml_layer.CODE_PATTERNS) == 0


def test_cross_validation_out_of_fold():
    pytest.importorskip('sklearn')
    rows = []
    for i in range(10):
        for variant, label in ml_layer.VARIANTS:
            feats = {k: (i + label) % 3 for k in ml_layer.FEATURES}
            rows.append(dict(benchmark='b%d' % i, variant=variant, label=label, **feats))
    folds, oof = ml_layer.cross_validate(rows)
    assert len(folds) == 5 and len(oof) == 20
    assert {(r['benchmark'], r['variant']) for r in oof} == {(r['benchmark'], r['variant']) for r in rows}
    assert all(0 <= r['prob'] <= 1 and r['pred'] == int(r['prob'] >= 0.5) for r in oof)
