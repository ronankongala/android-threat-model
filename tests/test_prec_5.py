"""P-5: external_storage_io confidence from the path below the external folder.
Shaped after UniqueIDs-IdentityLeak-Lean (Secure writes "UNIQUE_ID.txt"),
ExposedCredentials-InformationExposure-Lean ("secretKeyStore") and
InternalToExternalStorage-InformationLeak-Lean (file name from an intent extra)."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import code_analyzer  # noqa: E402

MANIFEST = ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">'
            '<application/></manifest>')

HEAD = """.class public La/b/Main;
.super Landroid/app/Activity;

.method public run(Landroid/content/Intent;)V
    .locals 8
"""
EXT_DIR = """    const/4 v2, 0x0
    invoke-virtual {p0, v2}, La/b/Main;->getExternalFilesDir(Ljava/lang/String;)Ljava/io/File;
    move-result-object v1
"""
WRITE = """    new-instance v0, Ljava/io/File;
    invoke-direct {v0, v1, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    new-instance v4, Ljava/io/FileOutputStream;
    invoke-direct {v4, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    return-void
.end method
"""


def _ext(tmp_path, name_code):
    (tmp_path / 'smali' / 'a' / 'b').mkdir(parents=True)
    (tmp_path / 'smali' / 'a' / 'b' / 'Main.smali').write_text(
        HEAD + EXT_DIR + name_code + WRITE, encoding='utf-8')
    (tmp_path / 'AndroidManifest.xml').write_text(MANIFEST, encoding='utf-8')
    return [f for f in code_analyzer.analyze(str(tmp_path)) if f['pattern'] == 'external_storage_io']


@pytest.mark.parametrize('name', ['UNIQUE_ID.txt', 'cache.tmp', 'bible.txt'])
def test_hardcoded_non_sensitive_low(tmp_path, name):
    hits = _ext(tmp_path, '    const-string v3, "%s"\n' % name)
    assert [f['confidence'] for f in hits] == ['low']
    assert 'no sensitive word' in hits[0]['evidence']


@pytest.mark.parametrize('name', ['secretKeyStore', 'user_password.txt', 'auth_TOKEN',
                                  'credentials.json', 'private.pem', 'ssn_bkup.jpg'])
def test_hardcoded_sensitive_medium(tmp_path, name):
    hits = _ext(tmp_path, '    const-string v3, "%s"\n' % name)
    assert [f['confidence'] for f in hits] == ['medium']
    assert 'contains' in hits[0]['evidence']


def test_intent_extra_path_medium(tmp_path):
    code = """    const-string v5, "filename"
    invoke-virtual {p1, v5}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
"""
    hits = _ext(tmp_path, code)
    assert [f['confidence'] for f in hits] == ['medium']
    assert 'intent extra' in hits[0]['evidence']


def test_bundle_from_extras_medium(tmp_path):
    code = """    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;
    move-result-object v6
    const-string v5, "name"
    invoke-virtual {v6, v5}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
"""
    assert [f['confidence'] for f in _ext(tmp_path, code)] == ['medium']


def test_literal_plus_extra_concat_medium(tmp_path):
    code = """    new-instance v6, Ljava/lang/StringBuilder;
    const-string v5, "cache_"
    invoke-direct {v6, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    const-string v5, "n"
    invoke-virtual {p1, v5}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v7
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v6
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v3
"""
    assert [f['confidence'] for f in _ext(tmp_path, code)] == ['medium']


def test_unknown_field_path_medium(tmp_path):
    code = '    sget-object v3, La/b/Main;->NAME:Ljava/lang/String;\n'
    hits = _ext(tmp_path, code)
    assert [f['confidence'] for f in hits] == ['medium']


def test_moved_literal_stays_literal(tmp_path):
    code = '    const-string v7, "cache.tmp"\n    move-object v3, v7\n'
    assert [f['confidence'] for f in _ext(tmp_path, code)] == ['low']
