"""Tests for Fix C: task-affinity-hijack also flags singleTask/singleInstance
activities (CWE-1021, medium), using synthetic manifest dicts."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import surface  # noqa: E402

PKG = 'edu.ksu.cs.benign'


def _activity(name, affinity=None, mode=None, ctype='activity'):
    return {
        'name': PKG + '.' + name,
        'type': ctype,
        'exported': False,
        'exported_attr': 'false',
        'intent_filters': [],
        'permission': None,
        'task_affinity': affinity,
        'launch_mode': mode,
    }


def _apk(*components):
    return {'package': PKG, 'permissions': [], 'components': list(components),
            'application': {}}


def _task(findings):
    return [f for f in findings if f['issue'] == 'task-affinity-hijack']


@pytest.mark.parametrize('mode', ['singleTask', 'singleInstance', '2', '3'])
def test_new_task_launch_mode_flagged_medium(mode):
    found = _task(surface.find(_apk(_activity('A', mode=mode))))
    assert len(found) == 1
    f = found[0]
    assert f['cwe'] == 'CWE-1021'
    assert f['confidence'] == 'medium'
    assert f['component'] == PKG + '.A'
    assert 'launchMode="%s"' % mode in f['evidence']


@pytest.mark.parametrize('mode', [None, 'standard', 'singleTop', '0', '1'])
def test_other_launch_modes_not_flagged(mode):
    assert _task(surface.find(_apk(_activity('A', mode=mode)))) == []


@pytest.mark.parametrize('affinity', [PKG, PKG + '.sub', ''])
def test_new_task_mode_flagged_with_own_or_empty_affinity(affinity):
    found = _task(surface.find(_apk(_activity('A', affinity=affinity, mode='singleTask'))))
    assert [f['confidence'] for f in found] == ['medium']


def test_foreign_affinity_alone_still_high():
    found = _task(surface.find(_apk(_activity('A', affinity='com.other.app'))))
    assert len(found) == 1
    assert found[0]['confidence'] == 'high'
    assert found[0]['evidence'] == 'android:taskAffinity="com.other.app"'


def test_both_rules_yield_one_high_finding():
    found = _task(surface.find(_apk(
        _activity('A', affinity='com.other.app', mode='singleInstance'))))
    assert len(found) == 1
    f = found[0]
    assert f['confidence'] == 'high'
    assert 'taskAffinity="com.other.app"' in f['evidence']
    assert 'launchMode="singleInstance"' in f['evidence']


def test_merge_keeps_high_over_medium_for_same_activity():
    medium = dict(surface._finding(_activity('A'), 'task-affinity-hijack', 'medium'))
    high = dict(surface._finding(_activity('A'), 'task-affinity-hijack', 'high'))
    merged = surface.merge([medium], [high])
    assert len(merged) == 1
    assert merged[0]['confidence'] == 'high'


def test_activity_alias_flagged():
    found = _task(surface.find(_apk(_activity('Alias', mode='singleTask',
                                              ctype='activity-alias'))))
    assert [f['confidence'] for f in found] == ['medium']


def test_non_activity_ignored():
    comp = _activity('S', mode='singleTask')
    comp['type'] = 'service'
    assert _task(surface.find(_apk(comp))) == []


def test_one_finding_per_activity():
    found = _task(surface.find(_apk(
        _activity('A', mode='singleTask'),
        _activity('B', mode='singleInstance'),
        _activity('C'))))
    assert sorted(f['component'] for f in found) == [PKG + '.A', PKG + '.B']
