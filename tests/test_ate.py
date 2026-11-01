"""Tests for the android-threat-engine tool.

Fixture: the api27 debug APK of the Benign app of
ICC/DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean, built during the smoke
test (docs/notes/SETUP_LOG.md). The tests are skipped if that APK is missing.

Layer 3 tests (call_graph.py, taint_analyzer.py) use the Benign apps of
Storage/SQLlite-RawQuery-SQLInjection-Lean and
Storage/InternalStorage-DirectoryTraversal-Lean, plus the smoke test fixture,
whose receiver forwards an intent extra to startActivity.

The Layer 4 test (dynamic_analyzer.py) installs the smoke test fixture on the
ghera27 emulator and is skipped when adb sees no device.

Layer 2 tests (code_analyzer.py) use the Benign api27 APK of the Ghera benchmark
that exhibits each pattern (PATTERN_FIXTURES). A test is skipped when its APK
has not been built.
"""
import json
import os
import shutil
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

import apk  # noqa: E402
import call_graph  # noqa: E402
import code_analyzer  # noqa: E402
import dynamic_analyzer  # noqa: E402
import report  # noqa: E402
import surface  # noqa: E402
import taint_analyzer  # noqa: E402

APK_REL = os.path.join('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')


def ghera_apk(bench, variant='Benign'):
    """Path of the api27 debug APK of benchmarks/ghera/<bench>/<variant>."""
    return os.path.join(ROOT, 'benchmarks', 'ghera', *bench.split('/'), variant, APK_REL)


FIXTURE_APK = ghera_apk('ICC/DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean')

# pattern -> Ghera benchmark whose Benign app has it
PATTERN_FIXTURES = {
    'ecb_mode': 'Crypto/BlockCipher-ECB-InformationExposure-Lean',
    'constant_iv': 'Crypto/BlockCipher-NonRandomIV-InformationExposure-Lean',
    'hardcoded_key': 'Crypto/ConstantKey-ForgeryAttack-Lean',
    'hardcoded_key_pbe': 'Crypto/PBE-ConstantSalt-InformationExposure-Lean',
    'empty_trustmanager': 'Networking/InvalidCertificateAuthority-MITM-Lean',
    'hostname_not_verified': 'Networking/IncorrectHostNameVerification-MITM-Lean',
    'insecure_ssl_socket_factory': 'Networking/InsecureSSLSocketFactory-MITM-Lean',
    'js_enabled': 'Web/JavaScriptExecution-CodeInjection-Lean',
    'webview_file_access': 'Web/WebViewAllowFileAccess-UnauthorizedFileAccess-Lean',
    'sql_injection_raw': 'Storage/SQLlite-RawQuery-SQLInjection-Lean',
    'sql_injection_no_args': 'Storage/SQLlite-SQLInjection-Lean',
    'directory_traversal': 'Storage/InternalStorage-DirectoryTraversal-Lean',
    'clipboard_sensitive': 'System/ClipboardUse-InformationExposure-Lean',
    'dynamic_code_load': 'System/DynamicCodeLoading-CodeInjection-Lean',
    'sticky_broadcast': 'ICC/StickyBroadcast-DataInjection-Lean',
    'implicit_broadcast': 'ICC/DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean',
    'pending_intent_empty': 'ICC/EmptyPendingIntent-PrivEscalation-Lean',
    'no_validity_check': 'ICC/NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean',
    'unique_ids': 'System/UniqueIDs-IdentityLeak-Lean',
}

_decoded_cache = {}


@pytest.fixture(scope='session')
def decode_dir():
    """Return a function that decodes an APK once per session and gives the
    apktool output folder (smali files)."""
    root = tempfile.mkdtemp(prefix='ate-test-')

    def get(path):
        if not os.path.exists(path):
            pytest.skip('fixture APK not built: %s' % os.path.relpath(path, ROOT))
        if path not in _decoded_cache:
            work = os.path.join(root, str(len(_decoded_cache)))
            os.makedirs(work)
            _decoded_cache[path] = apk.decode(path, work)
        return _decoded_cache[path]
    yield get
    shutil.rmtree(root, ignore_errors=True)


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


def _activity(name, categories, exported_attr='true'):
    return {'name': name, 'type': 'activity', 'exported': True,
            'exported_attr': exported_attr, 'permission': None,
            'intent_filters': [{'actions': ['android.intent.action.MAIN'],
                                'categories': categories}] if categories else []}


def test_surface_finds_exported_no_permission(findings):
    # The fixture's only exported component is its launcher, which is skipped.
    assert not [f for f in findings if f['issue'] == 'exported-no-permission']
    for f in findings:
        assert f['issue'] in surface.ISSUES
        assert f['cwe'] == surface.CWE[f['issue']]
        assert f['confidence'] in surface.CONFIDENCE
    manifest = {'components': [
        _activity('a.Launcher', ['android.intent.category.LAUNCHER']),
        _activity('a.Exposed', None),
    ]}
    issues = [f for f in surface.find(manifest) if f['issue'] == 'exported-no-permission']
    assert [f['component'] for f in issues] == ['a.Exposed']
    assert issues[0]['confidence'] == 'high'


def test_report_writes_both_files(tmp_path):
    findings = surface.find({'components': [_activity('a.Exposed', None)]})
    json_path, md_path = report.write(findings, 'fixture', str(tmp_path))
    assert os.path.basename(json_path) == 'fixture-report.json'
    assert os.path.basename(md_path) == 'fixture-report.md'
    with open(json_path, encoding='utf-8') as f:
        assert json.load(f) == findings
    with open(md_path, encoding='utf-8') as f:
        md = f.read()
    assert '| Component | Type | Issue | CWE | Confidence | Evidence |' in md
    assert 'exported-no-permission' in md


# Layer 2: static code analysis

@pytest.mark.parametrize('pattern', sorted(PATTERN_FIXTURES))
def test_code_pattern_detected(pattern, decode_dir):
    manifest = decode_dir(ghera_apk(PATTERN_FIXTURES[pattern]))
    found = [f for f in code_analyzer.analyze(manifest['decoded_dir']) if f['pattern'] == pattern]
    assert found, 'no %s finding' % pattern
    best = found[0]
    assert any(f['confidence'] in ('high', 'medium') for f in found)
    for key in ('component', 'file', 'line', 'pattern', 'cwe', 'confidence', 'evidence'):
        assert key in best
    assert best['cwe'] == code_analyzer.PATTERNS[pattern]
    assert best['evidence']


def test_surface_merges_code_findings(decode_dir):
    manifest = decode_dir(ghera_apk(PATTERN_FIXTURES['ecb_mode']))
    merged = surface.find(manifest)
    keys = [(f['component'], f['cwe']) for f in merged]
    assert len(keys) == len(set(keys)), 'duplicate (component, cwe) after merge'
    assert any(f['cwe'] == 'CWE-327' for f in merged)
    md = report.to_markdown(merged, 'ecb')
    assert 'Cipher;->getInstance' in md


# Layer 3: data flow analysis

TAINT_FIXTURES = {
    'sqlite_rawquery': ('Storage/SQLlite-RawQuery-SQLInjection-Lean', 'CWE-89'),
    'directory_traversal': ('Storage/InternalStorage-DirectoryTraversal-Lean', 'CWE-22'),
    'receiver_extra_to_activity': ('ICC/DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean', 'CWE-926'),
}


def test_call_graph_maps_callers_and_callees(decode_dir):
    manifest = decode_dir(FIXTURE_APK)
    graph, reverse = call_graph.build(manifest['decoded_dir'])
    assert graph, 'empty call graph'
    for caller, callees in graph.items():
        for callee in callees:
            assert caller in reverse[callee]


@pytest.mark.parametrize('case', sorted(TAINT_FIXTURES))
def test_taint_flow_detected(case, decode_dir):
    bench, cwe = TAINT_FIXTURES[case]
    manifest = decode_dir(ghera_apk(bench))
    found = [f for f in taint_analyzer.analyze(manifest['decoded_dir']) if f['cwe'] == cwe]
    assert found, 'no taint finding with %s' % cwe
    f = found[0]
    assert f['issue'] == 'taint-flow'
    assert f['confidence'] in ('high', 'medium', 'low')
    assert f['source_line'] and f['sink_line']
    assert 'source L' in f['evidence'] and 'sink L' in f['evidence']


# Layer 4: dynamic analysis

_adb = dynamic_analyzer.find_adb()
no_emulator = not (_adb and dynamic_analyzer.device_available(_adb))


@pytest.mark.skipif(no_emulator, reason='emulator not running')
def test_dynamic_receiver_accepts_external(decode_dir):
    manifest = decode_dir(FIXTURE_APK)
    found = dynamic_analyzer.run(FIXTURE_APK, manifest['package'], adb=_adb, manifest=manifest)
    accepted = [f for f in found if f['issue'] == 'dynamic-receiver-accepts-external']
    assert accepted, 'no dynamic-receiver-accepts-external finding: %r' % found
    assert accepted[0]['cwe'] in ('CWE-925', 'CWE-926')
