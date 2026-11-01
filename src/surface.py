"""Attack surface findings from the manifest dict returned by apk.decode().

find(apk) returns a list of findings, each a dict with:
  component, component_type, issue, cwe, confidence (high, medium or low)

The rules in this file read only the manifest dict. Of the ten issue
kinds in CWE below, four can be seen in a manifest and have rules here:

  exported-no-permission  exported component with no permission
  implicit-intent         component exported only because it has an intent filter
                          (no android:exported), reachable by implicit intents
  cleartext-http          app may send cleartext HTTP (usesCleartextTraffic, or the
                          pre-API 28 default) and requests INTERNET
  path-not-sanitized      exported content provider protected only by path
                          permissions, or granting URI permissions, so access
                          depends on the path the caller supplies

The other six (dynamic-receiver-no-permission, missing-certificate-validation,
sql-no-parameterization, js-enabled-webview, hardcoded-key, weak-cipher) are
properties of code, not of the manifest. They are listed for their CWE IDs;
the code rules in code_analyzer.py report these weaknesses under their own
pattern names (for example ecb_mode for weak-cipher).

CWE IDs are those used in docs/threat-models/ (see standards-reference.md).

find(apk, decoded_dir) also runs the smali rules in code_analyzer.py and the
source to sink taint analysis in taint_analyzer.py on the apktool output folder
and merges their findings with the manifest findings. Code and taint findings
carry extra keys (file, line, pattern, evidence; taint findings also
source_line and sink_line). The merged list
keeps one finding per (component, cwe): the one with the highest confidence.
"""
import code_analyzer
import taint_analyzer

CWE = {
    'exported-no-permission': 'CWE-926',
    'dynamic-receiver-no-permission': 'CWE-926',
    'implicit-intent': 'CWE-927',
    'cleartext-http': 'CWE-319',
    'missing-certificate-validation': 'CWE-295',
    'sql-no-parameterization': 'CWE-89',
    'path-not-sanitized': 'CWE-22',
    'js-enabled-webview': 'CWE-749',
    'hardcoded-key': 'CWE-321',
    'weak-cipher': 'CWE-327',
}

ISSUES = tuple(CWE)
CONFIDENCE = ('high', 'medium', 'low')


def _finding(comp, issue, confidence):
    return {
        'component': comp['name'] if comp else '(application)',
        'component_type': comp['type'] if comp else 'application',
        'issue': issue,
        'cwe': CWE[issue],
        'confidence': confidence,
    }


def _is_launcher(comp):
    return any('android.intent.action.MAIN' in f['actions'] and
               'android.intent.category.LAUNCHER' in f['categories']
               for f in comp['intent_filters'])


def _protected(comp):
    if comp.get('permission'):
        return True
    if comp['type'] == 'provider':
        return bool(comp.get('read_permission') and comp.get('write_permission'))
    return False


def _exported_no_permission(comp):
    """Confidence: high when exported on purpose (android:exported="true") and not a
    launcher; medium when exported through an intent filter; low for the launcher
    activity, which must be exported for the app to start."""
    if not comp['exported'] or _protected(comp):
        return None
    if _is_launcher(comp):
        return 'low'
    if comp.get('exported_attr') == 'true':
        return 'high'
    return 'medium'


def _implicit_intent(comp):
    if not comp['exported'] or comp.get('exported_attr') is not None:
        return None
    if not comp['intent_filters'] or _is_launcher(comp) or comp['type'] == 'provider':
        return None
    # Filters on platform actions only (BOOT_COMPLETED and so on) are less likely to
    # carry app data than custom actions.
    actions = [a for f in comp['intent_filters'] for a in f['actions'] if a]
    custom = [a for a in actions if not a.startswith('android.')]
    return 'medium' if custom else 'low'


def _path_not_sanitized(comp):
    if comp['type'] != 'provider' or not comp['exported']:
        return None
    if comp.get('path_permissions') and not comp.get('permission'):
        return 'medium'
    if comp.get('grant_uri_permissions'):
        return 'low'
    return None


def _cleartext(apk):
    if 'android.permission.INTERNET' not in apk.get('permissions', []):
        return None
    app = apk.get('application') or {}
    flag = app.get('usesCleartextTraffic')
    if flag == 'true':
        return 'high'
    if flag == 'false' or app.get('networkSecurityConfig'):
        # A network security config can still allow cleartext; it is not read here.
        return None
    target = apk.get('target_sdk')
    if target is not None and target < 28:
        return 'low'   # cleartext allowed by default before API 28
    return None


def merge(*lists):
    """Concatenate finding lists, keeping one finding per (component, cwe).

    The finding with the highest confidence wins; on a tie the earlier one is
    kept. Order follows the first appearance of each (component, cwe).
    """
    rank = {c: i for i, c in enumerate(CONFIDENCE)}
    best = {}
    for findings in lists:
        for f in findings:
            key = (f.get('component'), f.get('cwe'))
            cur = best.get(key)
            if cur is None or rank.get(f.get('confidence'), 99) < rank.get(cur.get('confidence'), 99):
                best[key] = f
    return list(best.values())


def find(apk, decoded_dir=None):
    """Return the findings for the manifest dict `apk`, plus code findings when
    `decoded_dir` (or apk['decoded_dir']) names the apktool output folder."""
    decoded_dir = decoded_dir or apk.get('decoded_dir')
    findings = _manifest_findings(apk)
    if decoded_dir:
        findings = merge(findings, code_analyzer.analyze(decoded_dir),
                         taint_analyzer.analyze(decoded_dir))
    return findings


def _manifest_findings(apk):
    findings = []
    for comp in apk.get('components', []):
        for issue, rule in (('exported-no-permission', _exported_no_permission),
                            ('implicit-intent', _implicit_intent),
                            ('path-not-sanitized', _path_not_sanitized)):
            conf = rule(comp)
            if conf:
                findings.append(_finding(comp, issue, conf))
    conf = _cleartext(apk)
    if conf:
        findings.append(_finding(None, 'cleartext-http', conf))
    return findings
