"""Compare a privacy policy with what the APK manifest and code declare.

check(policy_text, apk) returns a list of contradiction findings. `apk` is the
dict from apk.decode(); when it has a 'decoded_dir' key (decode was called
with a workdir) the smali folders are also searched for SDK packages, otherwise
only manifest component names are used.

Each finding is a dict:
  rule       short rule name (for example 'location-not-collected')
  claim      the policy sentence that makes the claim
  evidence   what in the APK contradicts it
  severity   'high', 'medium' or 'low'

The rules are keyword based and look for negative claims ("we do not collect
location", "data stays on your device", "we do not share data with third
parties"). A finding is a contradiction between the text and the permissions
or packages the APK declares, not proof that data is collected or sent: a
declared permission may be unused, and an SDK may be present but disabled.

load_policy(path) reads a policy file as UTF-8 text.
"""
import os
import re

NEGATION = r"(?:do not|don't|does not|doesn't|never|will not|won't|not|no)"

# Sensitive data kinds: words that name the data in a policy, and the
# permissions that give access to it with the severity of each.
DATA_KINDS = {
    'location': (r'(?:location|gps|whereabouts)',
                 {'android.permission.ACCESS_FINE_LOCATION': 'high',
                  'android.permission.ACCESS_BACKGROUND_LOCATION': 'high',
                  'android.permission.ACCESS_COARSE_LOCATION': 'medium'}),
    'contacts': (r'contacts?',
                 {'android.permission.READ_CONTACTS': 'high',
                  'android.permission.GET_ACCOUNTS': 'low'}),
    'camera': (r'(?:camera|photos?)',
               {'android.permission.CAMERA': 'medium'}),
    'microphone': (r'(?:microphone|audio|voice)',
                   {'android.permission.RECORD_AUDIO': 'high'}),
    'sms': (r'(?:sms|text messages?)',
            {'android.permission.READ_SMS': 'high',
             'android.permission.RECEIVE_SMS': 'high'}),
    'call log': (r'(?:call logs?|phone calls?)',
                 {'android.permission.READ_CALL_LOG': 'high'}),
}
COLLECT_VERBS = r'(?:collect|access|track|gather|record|store|use|request|read|log)'

# Package prefixes of advertising and analytics SDKs. Advertising SDKs are high
# severity against a "no third-party sharing" claim, analytics medium.
AD_PACKAGES = ('com.google.android.gms.ads', 'com.facebook.ads', 'com.mopub',
               'com.applovin', 'com.unity3d.ads', 'com.ironsource')
ANALYTICS_PACKAGES = ('com.google.firebase.analytics', 'com.google.android.gms.analytics',
                      'com.google.firebase.crashlytics', 'com.crashlytics', 'com.flurry',
                      'com.appsflyer', 'com.adjust.sdk', 'com.mixpanel', 'com.amplitude',
                      'io.sentry', 'com.segment.analytics')

ON_DEVICE_RE = re.compile(
    r'(?:\b(?:stays?|remains?|kept|stored|saved|lives?)\s+(?:only\s+|locally\s+)?(?:on|in)\s+'
    r'(?:your|the)\s+(?:own\s+)?(?:device|phone)'
    r'|\bnever\s+leaves?\s+(?:your|the)\s+(?:device|phone)'
    r'|\b(?:not|never)\s+(?:be\s+)?(?:sent|transmitted|uploaded|transferred)\s+to\s+'
    r'(?:any|our|a|the)\s+(?:\w+\s+)?servers?'
    r'|\bno\s+(?:network|internet)\s+(?:access|connection|permission))', re.I)
NO_SHARING_RE = re.compile(
    NEGATION + r"\s+(?:\w+\s+){0,3}(?:share|sell|disclose|transfer|give|provide|pass)\w*"
    r"[^.]{0,120}?\b(?:third|3rd)[- ]part(?:y|ies)", re.I)
NO_SHARING_RE2 = re.compile(r'\b(?:no|not)\s+(?:\w+\s+){0,2}(?:shared|sold|disclosed)\s+'
                            r'(?:\w+\s+){0,2}(?:with|to)\s+(?:any\s+)?(?:third|3rd)[- ]part', re.I)
NO_TRACKING_RE = re.compile(r'\b(?:no|without|' + NEGATION[3:-1] + r')\s+(?:[\w-]+\s+){0,3}'
                            r'(?:ads|advertis\w*|tracking|trackers|analytics)\b', re.I)


def load_policy(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read()


def sentences(text):
    """Split policy text into sentences (and list items), whitespace collapsed.
    Markdown emphasis (**bold**, __bold__) is removed first, since a policy
    kept in a README writes claims like "__No Internet access:__"."""
    text = re.sub(r'\*{2,3}|(?<!\w)_{1,3}|_{1,3}(?!\w)', ' ', text)
    text = re.sub(r'[ \t]+', ' ', text)
    parts = re.split(r'(?<=[.!?])\s+|\n\s*\n|(?:^|\n)\s*[-*•]\s+', text)
    return [re.sub(r'\s+', ' ', p).strip() for p in parts if p and p.strip()]


def sdk_packages(apk):
    """Advertising and analytics package prefixes found in the APK.

    Returns {prefix: where} with where 'code' (a smali folder exists) or
    'manifest' (a component name starts with the prefix)."""
    found = {}
    names = [c.get('name') or '' for c in apk.get('components', [])]
    decoded = apk.get('decoded_dir')
    smali_dirs = []
    if decoded and os.path.isdir(decoded):
        smali_dirs = [os.path.join(decoded, d) for d in os.listdir(decoded) if d.startswith('smali')]
    for prefix in AD_PACKAGES + ANALYTICS_PACKAGES:
        if any(os.path.isdir(os.path.join(d, *prefix.split('.'))) for d in smali_dirs):
            found[prefix] = 'code'
        elif any(n == prefix or n.startswith(prefix + '.') for n in names):
            found[prefix] = 'manifest'
    return found


def _finding(rule, claim, evidence, severity):
    return {'rule': rule, 'claim': claim, 'evidence': evidence, 'severity': severity}


def _data_kind_findings(sent, perms):
    out = []
    for kind, (word, kind_perms) in DATA_KINDS.items():
        rx = re.compile(NEGATION + r'\s+(?:\w+\s+){0,3}' + COLLECT_VERBS + r'\w*\b[^.]{0,60}?\b'
                        + word + r'\b', re.I)
        if not rx.search(sent):
            continue
        for perm, sev in kind_perms.items():
            if perm in perms:
                out.append(_finding('%s-not-collected' % kind.replace(' ', '-'), sent,
                                    'manifest requests %s' % perm, sev))
    return out


def check(policy_text, apk):
    """Contradiction findings between `policy_text` and the APK dict `apk`."""
    perms = set(apk.get('permissions', []))
    sdks = sdk_packages(apk)
    ads = sorted(p for p in sdks if p in AD_PACKAGES)
    analytics = sorted(p for p in sdks if p in ANALYTICS_PACKAGES)
    findings, seen = [], set()

    def add(f):
        key = (f['rule'], f['claim'], f['evidence'])
        if key not in seen:
            seen.add(key)
            findings.append(f)

    for sent in sentences(policy_text):
        for f in _data_kind_findings(sent, perms):
            add(f)
        if ON_DEVICE_RE.search(sent) and 'android.permission.INTERNET' in perms:
            # INTERNET alone is medium: the app may use it only for opt-in sync.
            # With an advertising or analytics SDK, data has an obvious way out.
            sev = 'high' if ads or analytics else 'medium'
            ev = 'manifest requests android.permission.INTERNET'
            if ads or analytics:
                ev += '; SDK packages: %s' % ', '.join(ads + analytics)
            add(_finding('data-stays-on-device', sent, ev, sev))
        if NO_SHARING_RE.search(sent) or NO_SHARING_RE2.search(sent) or NO_TRACKING_RE.search(sent):
            for p in ads:
                add(_finding('no-third-party-sharing', sent,
                             'advertising SDK %s (found in %s)' % (p, sdks[p]), 'high'))
            for p in analytics:
                add(_finding('no-third-party-sharing', sent,
                             'analytics SDK %s (found in %s)' % (p, sdks[p]), 'medium'))
    order = {'high': 0, 'medium': 1, 'low': 2}
    findings.sort(key=lambda f: order[f['severity']])
    return findings


def to_markdown(findings, policy_name=None):
    """Lines for the "Privacy Policy Analysis" section of the report."""
    lines = ['## Privacy Policy Analysis', '']
    if policy_name:
        lines += ['Policy file: `%s`' % policy_name, '']
    if not findings:
        return lines + ['No contradictions between the policy and the manifest were found.']
    lines += ['| Severity | Rule | Policy claim | Manifest evidence |', '|---|---|---|---|']
    for f in findings:
        cells = [f['severity'], f['rule'], f['claim'], f['evidence']]
        lines.append('| ' + ' | '.join(str(c).replace('|', '\\|') for c in cells) + ' |')
    return lines
