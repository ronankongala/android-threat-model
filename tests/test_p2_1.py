"""Tests for P2-1: class hierarchy taint analysis, using synthetic smali.

A tainted value is passed to a method through its base type; the base method
has no sink, but an override in a subclass (up to two levels below the base)
does, so the flow must be reported. Overrides three levels down are not
followed.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import taint_analyzer  # noqa: E402

PKG = 'com/example/app'


def _cls(name, sup, methods, implements=()):
    lines = ['.class public L%s/%s;' % (PKG, name), '.super %s' % sup]
    lines += ['.implements %s' % i for i in implements]
    lines.append('')
    for m in methods:
        lines += m.strip('\n').split('\n')
        lines.append('')
    return '\n'.join(lines) + '\n'


INIT = """
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
"""

BASE_HANDLE = """
.method public handle(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)V
    .locals 0
    return-void
.end method
"""

SINK_HANDLE = """
.method public handle(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)V
    .locals 1
    const/4 v0, 0x0
    invoke-virtual {p1, p2, v0}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
    return-void
.end method
"""

ABSTRACT_HANDLE = """
.method public abstract handle(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)V
.end method
"""


def _caller(owner, invoke='invoke-virtual'):
    return """
.method public run(Landroid/content/Intent;Landroid/database/sqlite/SQLiteDatabase;L%s/%s;)V
    .locals 1
    const-string v0, "q"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    %s {p3, p2, v0}, L%s/%s;->handle(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)V
    return-void
.end method
""" % (PKG, owner, invoke, PKG, owner)


def _write(tmp_path, classes):
    root = tmp_path / 'decoded' / 'smali' / PKG
    root.mkdir(parents=True)
    for name, text in classes.items():
        (root / (name + '.smali')).write_text(text)
    return str(tmp_path / 'decoded')


def _flows(decoded, cls=None):
    out = [f for f in taint_analyzer.analyze(decoded) if f['cwe'] == 'CWE-89']
    if cls:
        out = [f for f in out if f['component'] == cls]
    return out


def test_subclass_override_with_sink_is_followed(tmp_path):
    decoded = _write(tmp_path, {
        'Base': _cls('Base', 'Ljava/lang/Object;', [INIT, BASE_HANDLE]),
        'Sub': _cls('Sub', 'L%s/Base;' % PKG, [INIT, SINK_HANDLE]),
        'Caller': _cls('Caller', 'Ljava/lang/Object;', [INIT, _caller('Base')]),
    })
    found = _flows(decoded, 'com.example.app.Sub')
    assert len(found) == 1
    f = found[0]
    assert f['pattern'] == 'taint:getStringExtra->rawQuery'
    assert f['confidence'] == 'medium'   # one call level crossed
    assert f['file'].endswith('Sub.smali')


def test_two_levels_below_owner_is_followed(tmp_path):
    decoded = _write(tmp_path, {
        'Base': _cls('Base', 'Ljava/lang/Object;', [INIT, BASE_HANDLE]),
        'Mid': _cls('Mid', 'L%s/Base;' % PKG, [INIT]),
        'Leaf': _cls('Leaf', 'L%s/Mid;' % PKG, [INIT, SINK_HANDLE]),
        'Caller': _cls('Caller', 'Ljava/lang/Object;', [INIT, _caller('Base')]),
    })
    assert len(_flows(decoded, 'com.example.app.Leaf')) == 1


def test_three_levels_below_owner_not_followed(tmp_path):
    decoded = _write(tmp_path, {
        'Base': _cls('Base', 'Ljava/lang/Object;', [INIT, BASE_HANDLE]),
        'A': _cls('A', 'L%s/Base;' % PKG, [INIT]),
        'B': _cls('B', 'L%s/A;' % PKG, [INIT]),
        'C': _cls('C', 'L%s/B;' % PKG, [INIT, SINK_HANDLE]),
        'Caller': _cls('Caller', 'Ljava/lang/Object;', [INIT, _caller('Base')]),
    })
    assert _flows(decoded) == []


def test_no_flow_without_hierarchy(tmp_path):
    # Sub does not extend Base: its sink must not be reached.
    decoded = _write(tmp_path, {
        'Base': _cls('Base', 'Ljava/lang/Object;', [INIT, BASE_HANDLE]),
        'Other': _cls('Other', 'Ljava/lang/Object;', [INIT, SINK_HANDLE]),
        'Caller': _cls('Caller', 'Ljava/lang/Object;', [INIT, _caller('Base')]),
    })
    assert _flows(decoded) == []


def test_interface_implementation_is_followed(tmp_path):
    iface = ('.class public abstract interface L%s/Handler;\n'
             '.super Ljava/lang/Object;\n\n%s\n' % (PKG, ABSTRACT_HANDLE.strip()))
    decoded = _write(tmp_path, {
        'Handler': iface,
        'Impl': _cls('Impl', 'Ljava/lang/Object;', [INIT, SINK_HANDLE],
                     implements=['L%s/Handler;' % PKG]),
        'Caller': _cls('Caller', 'Ljava/lang/Object;',
                       [INIT, _caller('Handler', 'invoke-interface')]),
    })
    assert len(_flows(decoded, 'com.example.app.Impl')) == 1


def test_untainted_argument_does_not_follow_overrides(tmp_path):
    caller = _caller('Base').replace(
        'invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra'
        '(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n', '')
    decoded = _write(tmp_path, {
        'Base': _cls('Base', 'Ljava/lang/Object;', [INIT, BASE_HANDLE]),
        'Sub': _cls('Sub', 'L%s/Base;' % PKG, [INIT, SINK_HANDLE]),
        'Caller': _cls('Caller', 'Ljava/lang/Object;', [INIT, caller]),
    })
    assert _flows(decoded) == []
