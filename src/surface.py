"""Attack surface findings from the manifest dict returned by apk.decode().

find(apk) returns a list of findings, each a dict with:
  component, component_type, issue, cwe, confidence (high, medium or low)

The rules in this file read only the manifest dict. Of the twelve issue
kinds in CWE below, six can be seen in a manifest and have rules here:

  exported-no-permission  exported component with no permission. For a content
                          provider (exported explicitly, through an intent
                          filter or by the pre-API 17 default): high when it
                          has no android:permission, readPermission or
                          writePermission, medium when only one of
                          readPermission and writePermission is set
  implicit-intent         component exported only because it has an intent filter
                          (no android:exported), reachable by implicit intents
  cleartext-http          app may send cleartext HTTP (usesCleartextTraffic, the
                          pre-API 28 default, or a network security config that
                          permits cleartext) and requests INTERNET. Skipped when
                          the config permits cleartext only to localhost,
                          127.0.0.1 or 10.0.2.2 (the emulator's host), and when
                          usesCleartextTraffic="true" but minSdkVersion is below
                          23 (cleartext was the default before Android 6)
  path-not-sanitized      exported content provider protected only by path
                          permissions, or granting URI permissions, so access
                          depends on the path the caller supplies
  task-affinity-hijack    activity whose android:taskAffinity names another
                          package (not the app package or a name under it), so
                          it joins a task another app can own (confidence high;
                          the evidence also names a singleTask or singleInstance
                          launchMode). Also any activity with launchMode
                          singleTask or singleInstance (or apktool's numeric 2
                          or 3), whatever its taskAffinity, since it starts or
                          joins a task by affinity (confidence medium). An
                          activity hit by both rules yields one finding (high)

  provider-path-permission-only
                          exported content provider whose <path-permission>
                          children protect some paths while the provider itself
                          has no android:permission, readPermission or
                          writePermission, so every other path is open; also a
                          path-permission that uses android:path (exact match)
                          rather than pathPrefix or pathPattern, so subpaths of
                          that path are unprotected (confidence medium). Mapped
                          to CWE-284 as a candidate only: CWE-284 is DISCOURAGED
                          in standards-reference.md, so the finding carries a
                          'note' key saying children such as CWE-285 or CWE-732
                          are to be reviewed. The report lists findings with
                          a 'note' key under "Candidates to check"

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
import os
import xml.etree.ElementTree as ET

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
    'task-affinity-hijack': 'CWE-1021',
    # Candidate mapping. CWE-284 (Pillar) is DISCOURAGED in
    # docs/threat-models/standards-reference.md; it is used because the ground
    # truth of InadequatePathPermission-InformationExposure-Lean lists it.
    # Children such as CWE-285 or CWE-732 are to be reviewed.
    'provider-path-permission-only': 'CWE-284',
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


def _has_launcher_category(comp):
    return any('android.intent.category.LAUNCHER' in f['categories']
               for f in comp['intent_filters'])


def _provider_permissions(comp):
    return [k for k in ('permission', 'read_permission', 'write_permission') if comp.get(k)]


def _exported_no_permission(comp):
    """Confidence: high when exported on purpose (android:exported="true"); medium
    when exported through an intent filter. Launcher activities are skipped: they
    must be exported for the app to start, so they are not a vulnerability.

    Content providers (A2-2): high when the provider is exported (explicitly,
    or by the pre-API 17 default) and has none of android:permission,
    readPermission and writePermission, whatever <path-permission> children it
    has (those are reported separately as provider-path-permission-only);
    medium when only one of readPermission and writePermission is set."""
    if not comp['exported'] or _protected(comp):
        return None
    if comp['type'] == 'provider':
        return 'medium' if _provider_permissions(comp) else 'high'
    if comp['type'] in ('activity', 'activity-alias') and _has_launcher_category(comp):
        return None
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


def _provider_evidence(comp):
    how = ('android:exported="true"' if comp.get('exported_attr') == 'true'
           else 'exported by default (targetSdkVersion < 17)')
    present = _provider_permissions(comp)
    if not present:
        return ('%s with no android:permission, android:readPermission or '
                'android:writePermission: any app can query and modify it' % how)
    missing = 'android:writePermission' if comp.get('read_permission') else 'android:readPermission'
    return '%s with %s but no %s' % (how, ', '.join('android:' + {
        'permission': 'permission', 'read_permission': 'readPermission',
        'write_permission': 'writePermission'}[k] for k in present), missing)


PATH_PERMISSION_NOTE = ('candidate CWE-284 (DISCOURAGED in standards-reference.md; '
                        'children such as CWE-285/CWE-732 to be reviewed)')


def _pp_xml(pp):
    attrs = ' '.join('android:%s="%s"' % (k, pp[k]) for k in
                     ('path', 'pathPrefix', 'pathPattern', 'permission',
                      'readPermission', 'writePermission') if pp.get(k))
    return '<path-permission %s/>' % attrs if attrs else '<path-permission/>'


def _provider_path_permission(comp):
    """(confidence, evidence) for provider-path-permission-only, or None.

    Fires for an exported provider (comp['exported'] already applies the
    default export rule: providers were exported by default when
    targetSdkVersion < 17) that has <path-permission> children when either
      - the provider has no android:permission, readPermission or
        writePermission of its own, so paths outside the path-permissions are
        open to any app, or
      - a path-permission uses android:path (exact match) with no pathPrefix or
        pathPattern and the provider permissions do not cover everything, so
        subpaths of that path are unprotected.
    """
    if comp['type'] != 'provider' or not comp['exported']:
        return None
    pps = comp.get('path_permissions') or []
    if not pps or _protected(comp):
        return None
    reasons = []
    if not (comp.get('permission') or comp.get('read_permission')
            or comp.get('write_permission')):
        reasons.append('provider has no android:permission, android:readPermission '
                       'or android:writePermission, so other paths are unprotected')
    exact = [pp for pp in pps
             if pp.get('path') and not pp.get('pathPrefix') and not pp.get('pathPattern')]
    if exact:
        reasons.append('android:path (exact match) leaves subpaths unprotected: %s'
                       % ', '.join(pp['path'] for pp in exact))
    if not reasons:
        return None
    evidence = '%s; %s; %s' % (' '.join(_pp_xml(pp) for pp in pps),
                               '; '.join(reasons), PATH_PERMISSION_NOTE)
    return 'medium', evidence


LAUNCH_MODES_NEW_TASK = ('singleTask', 'singleInstance', '2', '3')


def _foreign_affinity(affinity, package):
    if not affinity or not package:
        return False   # an empty affinity means the activity belongs to no task
    return affinity != package and not affinity.startswith(package + '.')


def _task_affinity(comp, package):
    """(confidence, evidence) for the task-affinity-hijack rule, or None.

    high: the activity's taskAffinity points at another package.
    medium: the activity uses launchMode singleTask or singleInstance.
    """
    if comp['type'] not in ('activity', 'activity-alias'):
        return None
    affinity = comp.get('task_affinity')
    mode = comp.get('launch_mode')
    new_task = mode in LAUNCH_MODES_NEW_TASK
    if _foreign_affinity(affinity, package):
        evidence = 'android:taskAffinity="%s"' % affinity
        if new_task:
            evidence += ' with android:launchMode="%s"' % mode
        return 'high', evidence
    if new_task:
        return 'medium', 'android:launchMode="%s"' % mode
    return None


LOCAL_HOSTS = ('localhost', '127.0.0.1', '10.0.2.2')


def _nsc_cleartext_hosts(apk):
    """Domains for which the network security config permits cleartext ('*' for
    a base-config that permits it), or None when the config cannot be read."""
    ref = (apk.get('application') or {}).get('networkSecurityConfig') or ''
    decoded_dir = apk.get('decoded_dir')
    if not ref.startswith('@xml/') or not decoded_dir:
        return None
    path = os.path.join(decoded_dir, 'res', 'xml', ref[len('@xml/'):] + '.xml')
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None
    hosts = []
    base = root.find('base-config')
    if base is not None and base.get('cleartextTrafficPermitted') == 'true':
        hosts.append('*')

    def walk(elem, inherited):
        permitted = elem.get('cleartextTrafficPermitted')
        permitted = inherited if permitted is None else permitted == 'true'
        if permitted:
            hosts.extend((d.text or '').strip().lower() for d in elem.findall('domain'))
        for child in elem.findall('domain-config'):
            walk(child, permitted)
    for dc in root.findall('domain-config'):
        walk(dc, False)
    return hosts


def _cleartext(apk):
    if 'android.permission.INTERNET' not in apk.get('permissions', []):
        return None
    app = apk.get('application') or {}
    if app.get('networkSecurityConfig'):
        # From API 24 the config takes precedence over usesCleartextTraffic.
        hosts = _nsc_cleartext_hosts(apk)
        if not hosts or all(h in LOCAL_HOSTS for h in hosts):
            return None
        return 'high' if '*' in hosts else 'medium'
    flag = app.get('usesCleartextTraffic')
    if flag == 'true':
        min_sdk = apk.get('min_sdk')
        if min_sdk is not None and min_sdk < 23:
            return None   # cleartext was the default before Android 6: low value
        return 'high'
    if flag == 'false':
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
                f = _finding(comp, issue, conf)
                if issue == 'exported-no-permission' and comp['type'] == 'provider':
                    f['evidence'] = _provider_evidence(comp)
                findings.append(f)
        hit = _task_affinity(comp, apk.get('package'))
        if hit:
            f = _finding(comp, 'task-affinity-hijack', hit[0])
            f['evidence'] = hit[1]
            findings.append(f)
        hit = _provider_path_permission(comp)
        if hit:
            f = _finding(comp, 'provider-path-permission-only', hit[0])
            f['evidence'] = hit[1]
            f['note'] = PATH_PERMISSION_NOTE
            findings.append(f)
    conf = _cleartext(apk)
    if conf:
        findings.append(_finding(None, 'cleartext-http', conf))
    return findings
