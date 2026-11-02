"""P-6: a taint flow that passes a validation before the sink (matches,
contains and similar on the tainted value, an app method on the path that
calls one or throws, or a throw while the value is tainted) is reported low."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import taint_analyzer  # noqa: E402

PKG = 'com/example/app'
SOURCE = """    const-string v0, "q"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
"""
SINK = """    const/4 v1, 0x0
    invoke-virtual {p2, v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
"""
RUN = '.method public run(Landroid/content/Intent;Landroid/database/sqlite/SQLiteDatabase;)V'


def _cls(name, methods):
    return '.class public L%s/%s;\n.super Ljava/lang/Object;\n\n%s\n' % (
        PKG, name, '\n\n'.join(m.strip('\n') for m in methods))


def _run(body, locals_=3):
    return '%s\n    .locals %d\n%s    return-void\n.end method' % (RUN, locals_, body)


def _flows(tmp_path, classes):
    root = tmp_path / 'decoded' / 'smali' / PKG
    root.mkdir(parents=True)
    for name, text in classes.items():
        (root / (name + '.smali')).write_text(text)
    return [f for f in taint_analyzer.analyze(str(tmp_path / 'decoded')) if f['cwe'] == 'CWE-89']


def test_unvalidated_flow_high(tmp_path):
    found = _flows(tmp_path, {'A': _cls('A', [_run(SOURCE + SINK)])})
    assert [f['confidence'] for f in found] == ['high']
    assert 'validated' not in found[0]['evidence']


def test_matches_before_sink_low(tmp_path):
    check = """    const-string v2, "[a-z]+"
    invoke-virtual {v0, v2}, Ljava/lang/String;->matches(Ljava/lang/String;)Z
    move-result v2
"""
    found = _flows(tmp_path, {'A': _cls('A', [_run(SOURCE + check + SINK)])})
    assert [f['confidence'] for f in found] == ['low']
    assert 'validated on the path: matches()' in found[0]['evidence']


def test_contains_before_sink_low(tmp_path):
    check = """    const-string v2, "'"
    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v2
"""
    found = _flows(tmp_path, {'A': _cls('A', [_run(SOURCE + check + SINK)])})
    assert [f['confidence'] for f in found] == ['low']


def test_check_after_sink_does_not_count(tmp_path):
    check = """    const-string v2, "x"
    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v2
"""
    found = _flows(tmp_path, {'A': _cls('A', [_run(SOURCE + SINK + check)])})
    assert [f['confidence'] for f in found] == ['high']


def test_validation_method_on_path_low(tmp_path):
    validate = """.method public static check(Ljava/lang/String;)V
    .locals 1
    const-string v0, "^[0-9]+$"
    invoke-virtual {p0, v0}, Ljava/lang/String;->matches(Ljava/lang/String;)Z
    move-result v0
    if-nez v0, :ok
    new-instance v0, Ljava/lang/IllegalArgumentException;
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V
    throw v0
    :ok
    return-void
.end method"""
    call = '    invoke-static {v0}, L%s/V;->check(Ljava/lang/String;)V\n' % PKG
    found = _flows(tmp_path, {'A': _cls('A', [_run(SOURCE + call + SINK)]),
                              'V': _cls('V', [validate])})
    assert [f['confidence'] for f in found] == ['low']
    assert 'com.example.app.V.check' in found[0]['evidence']


def test_throw_before_sink_low(tmp_path):
    body = SOURCE + """    if-nez p2, :go
    new-instance v2, Ljava/lang/IllegalStateException;
    invoke-direct {v2}, Ljava/lang/IllegalStateException;-><init>()V
    throw v2
    :go
""" + SINK
    found = _flows(tmp_path, {'A': _cls('A', [_run(body)])})
    assert [f['confidence'] for f in found] == ['low']
    assert 'throw' in found[0]['evidence']


def test_validation_in_caller_lowers_callee_sink(tmp_path):
    sink = """.method public static q(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)V
    .locals 1
    const/4 v0, 0x0
    invoke-virtual {p0, p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
    return-void
.end method"""
    body = SOURCE + """    const-string v2, "x"
    invoke-virtual {v0, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z
    move-result v2
    invoke-static {p2, v0}, L%s/S;->q(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)V
""" % PKG
    found = _flows(tmp_path, {'A': _cls('A', [_run(body)]), 'S': _cls('S', [sink])})
    assert [f['confidence'] for f in found] == ['low']
    assert 'in a caller' in found[0]['evidence']
