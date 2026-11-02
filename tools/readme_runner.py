"""Replay the exploit steps of a Ghera benchmark README on a device through adb.

run_readme(readme_path, adb='adb', device=None, dry_run=False) -> list[dict]

Reads the numbered steps under the heading "Steps to build the sample apps and
to exploit the vulnerability" (matched loosely: any heading level, any case,
small wording changes), plans an action for each step and, unless dry_run is
set, runs it:

  install   "Build and install X" / gradlew install* / adb install: installs
            X/app/build/outputs/apk/api27/debug/app-api27-debug.apk
  launch    "Open / Launch / Start / Bring X ...": am start -n pkg/launcher
            (monkey on the LAUNCHER category when no launchable activity is known)
  tap       "click / tap / press <label>": uiautomator dump, find the node whose
            text or content-desc matches the label, input tap at its centre
  back      "press back" / "click the back button": input keyevent BACK
  adb       backticked commands that start with adb (or <sdk>/platform-tools/adb).
            "| grep X" is applied in Python; any other shell syntax is refused.
            "adb shell run-as PKG" followed by ls/cat/cd lines becomes
            "adb shell run-as PKG ls ..." (read-only commands only).
  observe   "check log": nothing to run, the logcat capture is the observation

Nothing other than adb is ever executed (plus aapt to read package names from
built APKs). After every step the runner captures `adb logcat -d` (then clears
it) and the foreground activity from `dumpsys activity activities`.

Each observation dict holds:
  step                 number written in the README (int, may repeat)
  index                0-based position of the step
  text                 step text, whitespace collapsed
  action               summary such as "launch Benign; tap 'Take Picture'",
                       or "skipped: <reason>"
  actions              [{type, target, status, commands, returncodes, output}]
                       status is ok, failed, planned or 'skipped: <reason>'
  commands             every adb command line run (or planned) for the step
  returncodes          their exit codes (empty in dry run)
  logcat               relevant logcat lines captured after the step
  signals              {'crashes': [...], 'permission_denials': [...],
                        'security_exceptions': [...], 'anr': [...]}
  foreground_activity  'pkg/cls' on top after the step, or None
  automatable          True when at least one action is not skipped

No adb or no device: every step is returned with action 'skipped: no device'
(the plan is still in 'actions'). Nothing raises for device trouble.

CLI: python tools/readme_runner.py <README|bench dir|ghera dir> [...]
         [--dry-run] [--json out.json] [--device SERIAL] [--adb PATH]
A directory argument expands to its README.md or to */*/README.md below it; with
more than one README a coverage summary is printed.
"""
import argparse
import glob
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

log = logging.getLogger('readme_runner')

try:  # keep adb discovery identical to the dynamic analyzer
    from dynamic_analyzer import find_adb as _find_adb  # noqa: E402
except Exception:  # pragma: no cover - src/ may be mid-edit
    _find_adb = None

DEFAULT_ADB = r'C:\Android\Sdk\platform-tools\adb.exe'
DEFAULT_SDK = r'C:\Android\Sdk'
APK_REL = os.path.join('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')
TIMEOUT = 30
INSTALL_TIMEOUT = 180
LAUNCH_WAIT = 2.5
TAP_WAIT = 1.5
MAX_LOG_LINES = 200

HEADING_RE = re.compile(r'^\s{0,3}(#{1,6})\s*(.*?)\s*#*\s*$')
STEP_RE = re.compile(r'^\s{0,3}(\d+)[.)]\s+(.*)$')
BACKTICK_RE = re.compile(r'`([^`]+)`', re.S)
ADB_PREFIX_RE = re.compile(r'^(?:\S*[/\\])?adb(?:\.exe)?$', re.I)
FOREGROUND_RE = re.compile(
    r'(?:mResumedActivity|mFocusedActivity|topResumedActivity|ResumedActivity)[:=]\s*'
    r'ActivityRecord\{[0-9a-f]+ u\d+ ([\w.$]+)/([\w.$]+) t(\d+)')
BOUNDS_RE = re.compile(r'\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]')
CRASH_RE = re.compile(r'FATAL EXCEPTION|Process: [\w.:]+, PID: \d+|has died|crashed', re.I)
PERM_RE = re.compile(r'Permission Denial|requires? (?:the )?(?:permission|android\.permission)|'
                     r'not allowed to|does not have permission', re.I)
SECEX_RE = re.compile(r'SecurityException')
ANR_RE = re.compile(r'\bANR in\b')

LAUNCH_VERBS = r'open|opens|launch|launches|start|starts|bring|run'
TAP_VERBS = r'click|clicks|tap|taps|press|presses'
SAFE_RUNAS_CMDS = {'ls', 'cat'}
SHELL_META = ('|', '>', '<', ';', '&&', '||', '`', '$(')


# ---------------------------------------------------------------- adb plumbing

def resolve_adb(adb='adb'):
    """Path to adb. 'adb' (the default) uses the dynamic analyzer's discovery."""
    if adb and adb != 'adb':
        return adb if (os.path.exists(adb) or shutil.which(adb)) else None
    if _find_adb is not None:
        return _find_adb()
    found = shutil.which('adb')
    if found:
        return found
    home = os.environ.get('ANDROID_HOME')
    exe = 'adb.exe' if os.name == 'nt' else 'adb'
    if home and os.path.exists(os.path.join(home, 'platform-tools', exe)):
        return os.path.join(home, 'platform-tools', exe)
    return DEFAULT_ADB if os.path.exists(DEFAULT_ADB) else None


class Adb:
    def __init__(self, path, device=None):
        self.path = path
        self.device = device

    def argv(self, args):
        pre = [self.path] + (['-s', self.device] if self.device else [])
        return pre + list(args)

    def run(self, args, timeout=TIMEOUT):
        """(exit code, stdout + stderr). Never raises."""
        try:
            r = subprocess.run(self.argv(args), capture_output=True, text=True,
                               encoding='utf-8', errors='replace', timeout=timeout)
            return r.returncode, (r.stdout or '') + (r.stderr or '')
        except subprocess.TimeoutExpired:
            log.warning('adb %s timed out after %ss', ' '.join(args), timeout)
            return -1, 'timeout'
        except OSError as e:
            log.warning('adb %s failed: %s', ' '.join(args), e)
            return -1, str(e)

    def available(self):
        code, out = self.run(['devices'], timeout=15) if not self.device else (None, None)
        if self.device:
            code, out = self.run(['get-state'], timeout=15)
            return code == 0 and out.strip().endswith('device')
        if code != 0:
            return False
        return any(l.rstrip('\r').endswith('\tdevice') for l in out.splitlines()[1:])


def cmdline(args):
    return 'adb ' + ' '.join(shlex.quote(a) for a in args)


# ---------------------------------------------------------------- README parsing

def find_steps_section(text):
    """Lines of the steps section, or None when the heading is absent."""
    lines = text.splitlines()
    start = level = None
    for i, line in enumerate(lines):
        m = HEADING_RE.match(line)
        bold = re.match(r'^\s*\*\*(.+?)\*\*\s*:?\s*$', line)
        title = m.group(2) if m else (bold.group(1) if bold else None)
        if title is None:
            continue
        if start is None:
            t = title.lower()
            if re.match(r'^steps?\b', t) and re.search(r'build|exploit|reproduce|run|demonstrat', t):
                start, level = i + 1, (len(m.group(1)) if m else 6)
        elif m and len(m.group(1)) <= level:
            return lines[start:i]
    if start is None:
        # looser fallback: any heading that starts with "steps"
        for i, line in enumerate(lines):
            m = HEADING_RE.match(line)
            if m and re.match(r'^steps?\b', m.group(2).lower()):
                return find_steps_section('# Steps to build and exploit\n' + '\n'.join(lines[i + 1:]))
        return None
    return lines[start:]


def parse_steps(text):
    """[{'step': n, 'index': i, 'text': collapsed text, 'raw': original text}]."""
    section = find_steps_section(text)
    if section is None:
        return []
    steps = []
    cur = None
    for line in section:
        m = STEP_RE.match(line)
        if m:
            cur = {'step': int(m.group(1)), 'raw_lines': [m.group(2)]}
            steps.append(cur)
        elif cur is not None:
            cur['raw_lines'].append(line)
    out = []
    for i, s in enumerate(steps):
        raw = '\n'.join(s['raw_lines']).strip()
        out.append({'step': s['step'], 'index': i, 'raw': raw,
                    'text': re.sub(r'\s+', ' ', raw).strip()})
    return out


# ---------------------------------------------------------------- bench context

def find_aapt():
    homes = [os.environ.get('ANDROID_HOME'), os.environ.get('ANDROID_SDK_ROOT'), DEFAULT_SDK]
    exe = 'aapt.exe' if os.name == 'nt' else 'aapt'
    for home in filter(None, homes):
        cands = sorted(glob.glob(os.path.join(home, 'build-tools', '*', exe)), reverse=True)
        if cands:
            return cands[0]
    return shutil.which('aapt')


def _aapt_info(apk):
    aapt = find_aapt()
    if not aapt:
        return None, None
    try:
        r = subprocess.run([aapt, 'dump', 'badging', apk], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    pkg = re.search(r"^package: name='([^']+)'", r.stdout, re.M)
    act = re.search(r"^launchable-activity: name='([^']+)'", r.stdout, re.M)
    return (pkg.group(1) if pkg else None), (act.group(1) if act else None)


def _source_info(app_dir):
    """Package and launcher activity from build.gradle / the source manifest."""
    pkg = act = None
    gradle = os.path.join(app_dir, 'app', 'build.gradle')
    manifest = os.path.join(app_dir, 'app', 'src', 'main', 'AndroidManifest.xml')
    try:
        with open(gradle, encoding='utf-8', errors='replace') as f:
            m = re.search(r'applicationId\s+["\']([\w.]+)["\']', f.read())
            pkg = m.group(1) if m else None
    except OSError:
        pass
    try:
        ns = '{http://schemas.android.com/apk/res/android}'
        root = ET.parse(manifest).getroot()
        mpkg = root.get('package')
        pkg = pkg or mpkg
        for a in root.iter('activity'):
            for f in a.iter('intent-filter'):
                acts = {e.get(ns + 'name') for e in f.iter('action')}
                cats = {e.get(ns + 'name') for e in f.iter('category')}
                if 'android.intent.action.MAIN' in acts and 'android.intent.category.LAUNCHER' in cats:
                    name = a.get(ns + 'name') or ''
                    act = (mpkg or pkg) + name if name.startswith('.') else (
                        name if '.' in name else '%s.%s' % (mpkg or pkg, name))
                    break
            if act:
                break
    except (OSError, ET.ParseError):
        pass
    return pkg, act


def bench_apps(bench_dir):
    """{app name: {'dir', 'apk' (or None), 'package', 'activity'}} for the bench."""
    apps = {}
    try:
        names = sorted(os.listdir(bench_dir))
    except OSError:
        return apps
    for name in names:
        d = os.path.join(bench_dir, name)
        if not os.path.isdir(os.path.join(d, 'app')):
            continue
        apk = os.path.join(d, APK_REL)
        apk = apk if os.path.exists(apk) else None
        pkg = act = None
        if apk:
            pkg, act = _aapt_info(apk)
        if not pkg or not act:
            spkg, sact = _source_info(d)
            pkg, act = pkg or spkg, act or sact
        apps[name] = {'dir': d, 'apk': apk, 'package': pkg, 'activity': act}
    return apps


# ---------------------------------------------------------------- planning

def _app_regex(apps):
    names = sorted(apps, key=len, reverse=True)
    if not names:
        return None
    return re.compile(r'(?<![\w-])(%s)(?![\w-])' % '|'.join(re.escape(n) for n in names))


def _clauses(text):
    # split on sentence ends and "then"; keep order
    parts = re.split(r'(?<=[.!?:])\s+(?=[A-Z*"])|\b(?:and then|then)\b|;', text)
    return [p.strip() for p in parts if p and p.strip()]


def _label_after(clause, pos):
    """Button label that follows a click verb ending at `pos`, or '' for a generic button."""
    rest = clause[pos:]
    rest = re.sub(r'^\s*(?:on\b|at\b)?\s*(?:(?:the|a|an|any)\b)?\s*', '', rest, flags=re.I)
    rest = re.sub(r'^(?:button|link|text)s?\s*(?:labell?ed|named|called|saying)?\s*[-:]?\s*'
                  r'(?=["“*])', '', rest, flags=re.I)
    m = re.match(r'(?:button|text|link|label)?\s*["\u201c]([^"\u201d]+)["\u201d]', rest, re.I) or \
        re.match(r'(?:button|text|link|label)?\s*\*([^*]+)\*', rest, re.I)
    if m:
        return m.group(1).strip()
    m = re.match(r'(?:back)\s*(?:button|key)?\b', rest, re.I)
    if m:
        return '<back>'
    if re.match(r'(?:button|buttons?\b)', rest, re.I):
        return ''
    m = re.match(r'([A-Z][\w\-!]*(?:\s+[A-Z][\w\-!]*){0,3})(?:\s+button)?', rest)
    if m:
        return m.group(1).strip()
    m = re.match(r'([\w\-! ]{1,30}?)\s+button\b', rest, re.I)
    if m:
        return m.group(1).strip()
    return None


def _mask_quoted(text):
    """`text` with the inside of "..." and *...* spans blanked (same length)."""
    return re.sub(r'(["“][^"”]*["”]|\*[^*]*\*)',
                  lambda m: m.group(0)[0] + '_' * (len(m.group(0)) - 2) + m.group(0)[-1], text)


def _commands(raw):
    """Backticked commands in order, '$ ' prompts stripped and lines joined."""
    cmds = []
    for m in BACKTICK_RE.finditer(raw):
        c = re.sub(r'\s+', ' ', m.group(1)).strip()
        c = re.sub(r'^\$\s*', '', c)
        if c:
            cmds.append(c)
    return cmds


def _plan_adb(cmd, ctx, bench_dir, apps):
    """Plan an adb command string. Returns an action dict."""
    grep = None
    if '|' in cmd:
        left, _, right = cmd.partition('|')
        gm = re.match(r'^\s*grep\s+(?:-\w+\s+)*["\']?([^"\']+?)["\']?\s*$', right)
        if not gm:
            return _skip('adb', cmd, 'shell pipeline not supported')
        cmd, grep = left.strip(), gm.group(1)
    if any(t in cmd for t in SHELL_META):
        return _skip('adb', cmd, 'shell syntax not supported')
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return _skip('adb', cmd, 'unparsable command')
    if not toks or not ADB_PREFIX_RE.match(toks[0]):
        return _skip('adb', cmd, 'not an adb command')
    args = toks[1:]
    # strip device selection; the runner adds its own -s
    clean = []
    i = 0
    while i < len(args):
        if args[i] in ('-s', '-t') and i + 1 < len(args):
            i += 2
            continue
        if args[i] in ('-d', '-e'):
            i += 1
            continue
        clean.append(args[i])
        i += 1
    args = clean
    if not args:
        return _skip('adb', cmd, 'empty adb command')
    if any('<' in a or '>' in a or '[' in a for a in args):
        return _skip('adb', cmd, 'unresolved placeholder')
    sub = args[0]
    if sub == 'logcat':
        args = ['logcat', '-d'] + [a for a in args[1:] if a != '-d']
        return {'type': 'adb', 'target': grep, 'argv': [args], 'grep': grep, 'cmd': cmd}
    if sub == 'install':
        path = args[-1]
        local = _resolve_local(path, ctx, bench_dir)
        if local:
            return {'type': 'install', 'target': path, 'argv': [['install', '-r', '-t', local]],
                    'cmd': cmd}
        app = ctx.get('cwd') if ctx.get('cwd') in apps else None
        if app and apps[app]['apk']:
            return {'type': 'install', 'target': app,
                    'argv': [['install', '-r', '-t', apps[app]['apk']]], 'cmd': cmd}
        return _skip('install', cmd, 'APK path does not exist and no built APK')
    if sub == 'push':
        if len(args) < 3:
            return _skip('adb', cmd, 'malformed push')
        local = _resolve_local(args[1], ctx, bench_dir)
        if not local:
            return _skip('adb', cmd, 'local file not found: %s' % args[1])
        return {'type': 'adb', 'target': args[2], 'argv': [['push', local, args[2]]], 'cmd': cmd}
    if sub == 'shell' and len(args) >= 2 and args[1] == 'run-as' and len(args) == 3:
        ctx['run_as'] = args[2]
        ctx['run_as_cwd'] = ''
        return None  # interactive shell: following ls/cat lines run under it
    if sub == 'shell' and len(args) == 1:
        return _skip('adb', cmd, 'interactive shell')
    return {'type': 'adb', 'target': sub, 'argv': [args], 'grep': grep, 'cmd': cmd}


def _resolve_local(path, ctx, bench_dir):
    cands = []
    if ctx.get('cwd'):
        cands.append(os.path.join(bench_dir, ctx['cwd'], path))
    cands.append(os.path.join(bench_dir, path))
    for c in cands:
        if os.path.isfile(c):
            return os.path.normpath(c)
    return None


def _skip(type_, target, reason):
    return {'type': type_, 'target': target, 'argv': [], 'status': 'skipped: ' + reason}


def plan_step(step, apps, bench_dir):
    """Ordered list of action dicts for one parsed step."""
    actions = []
    raw, text = step['raw'], step['text']
    app_re = _app_regex(apps)
    ctx = {'cwd': None, 'run_as': None}
    installed = set()

    # 1. backticked commands
    pending_gradle = None
    for cmd in _commands(raw):
        cmd = re.sub(r'^\S*[/\\]adb(?:\.exe)?(?=\s|$)', 'adb', cmd)
        first = cmd.split()[0] if cmd.split() else ''
        if first == 'cd':
            target = cmd.split(None, 1)[1].strip() if len(cmd.split()) > 1 else ''
            if ctx.get('run_as'):
                ctx['run_as_cwd'] = target
            else:
                ctx['cwd'] = target.strip('/\\')
            continue
        if ctx.get('run_as') and first in SAFE_RUNAS_CMDS:
            extra = cmd.split()[1:]
            if any(t in cmd for t in SHELL_META):
                actions.append(_skip('adb', cmd, 'shell syntax not supported'))
                continue
            opts = [e for e in extra if e.startswith('-')]
            paths = [e for e in extra if not e.startswith('-')]
            base = ctx.get('run_as_cwd') or ''
            if base:
                paths = [base + '/' + p for p in paths] or [base]
            args = ['shell', 'run-as', ctx['run_as'], first] + opts + paths
            actions.append({'type': 'adb', 'target': 'run-as ' + ctx['run_as'],
                            'argv': [args], 'cmd': cmd})
            continue
        if re.search(r'gradlew?\b.*\binstall', cmd, re.I):
            app = ctx.get('cwd')
            if app in apps:
                actions.append(_install(app, apps))
                installed.add(app)
            else:
                pending_gradle = _skip('install', cmd, 'unknown app directory %r' % app)
            continue
        if ADB_PREFIX_RE.match(first):
            a = _plan_adb(cmd, ctx, bench_dir, apps)
            if a is not None:
                actions.append(a)
            continue
        if first in ('avdmanager', 'emulator', 'sdkmanager'):
            actions.append(_skip('setup', cmd, 'emulator setup (device assumed running)'))
            continue
        actions.append(_skip('shell', cmd, 'not an adb command'))

    # 2. "Build and install X" without commands
    if re.search(r'\binstall\b', text, re.I) and app_re is not None and \
            re.search(r'\b(?:build|install)\b', text.split('.')[0], re.I):
        for m in app_re.finditer(text.split(':')[0]):
            if m.group(1) not in installed:
                actions.append(_install(m.group(1), apps))
                installed.add(m.group(1))
    if pending_gradle and not installed:
        actions.append(pending_gradle)

    n_cmd_actions = len(actions)
    # 3. natural language launch / tap / back / observe, in text order
    prose = BACKTICK_RE.sub(' ', raw)
    prose = re.sub(r'\s+', ' ', prose).strip()
    for clause in _clauses(prose):
        events = []
        masked = _mask_quoted(clause)
        for m in re.finditer(r'\b(%s)\b' % LAUNCH_VERBS, masked, re.I):
            if re.search(r'\b(?:will|would|should|to|may|can|it)\s+$', masked[:m.start()], re.I):
                continue  # "It will start X's activity" describes, it does not instruct
            seg = clause[m.end():]
            stop = re.search(r'\b(?:%s|enter|type)\b' % TAP_VERBS, masked[m.end():], re.I)
            seg = seg[:stop.start()] if stop else seg
            targets = [a.group(1) for a in app_re.finditer(seg)] if app_re else []
            if not targets and re.match(r'\s*the app\b', seg, re.I) and apps:
                targets = ['Benign'] if 'Benign' in apps else [sorted(apps)[0]]
            if re.match(r'\s*(?:the )?(?:emulator|server)\b', seg, re.I):
                targets = []
            for t in dict.fromkeys(targets):
                events.append((m.start(), _launch(t, apps)))
        for m in re.finditer(r'\b(%s)\b' % TAP_VERBS, masked, re.I):
            if m.group(1).lower().startswith('press') and \
                    re.match(r'\s+(?:the\s+)?back\b', clause[m.end():], re.I) is None and \
                    re.match(r'\s+(?:\*|"|the\b|on\b|[A-Z])', clause[m.end():]) is None:
                continue
            label = _label_after(clause, m.end())
            if label is None:
                continue
            if label == '<back>':
                events.append((m.start(), {'type': 'back', 'target': 'BACK',
                                           'argv': [['shell', 'input', 'keyevent', '4']]}))
            else:
                events.append((m.start(), {'type': 'tap', 'target': label, 'argv': []}))
        if re.search(r'\bback\b', clause, re.I) and not any(e[1]['type'] == 'back' for e in events) \
                and re.search(r'\b(?:%s)\b.*\bback\b' % TAP_VERBS, clause, re.I):
            events.append((len(clause), {'type': 'back', 'target': 'BACK',
                                         'argv': [['shell', 'input', 'keyevent', '4']]}))
        if re.search(r'\bcheck\b.*\blog(?:cat|s)?\b|\blogcat\b', clause, re.I) and \
                not any(a['type'] == 'adb' and 'logcat' in (a.get('target') or '') for a in actions):
            events.append((len(clause), {'type': 'observe', 'target': 'logcat', 'argv': []}))
        if re.search(r'\b(enter|type)\b', masked, re.I) and \
                not any(e[1]['type'] == 'tap' for e in events):
            events.append((0, _skip('input', clause[:60], 'text entry not automated')))
        gm = re.search(r'(?:^|\band\s+)grant\b.*\bpermission', masked, re.I)
        if gm:
            # runtime permission dialog: press its Allow button
            events.append((gm.start(), {'type': 'tap', 'target': 'Allow', 'argv': []}))
        for _, e in sorted(events, key=lambda x: x[0]):
            actions.append(e)

    # order: installs, then UI actions in text order, then adb commands
    # (verification commands such as run-as ls follow the launch they check)
    cmd_actions, prose_actions = actions[:n_cmd_actions], actions[n_cmd_actions:]
    first = [a for a in actions if a['type'] in ('install', 'setup', 'shell')]
    ids = {id(a) for a in first}
    ordered = first + [a for a in prose_actions if id(a) not in ids] + \
        [a for a in cmd_actions if id(a) not in ids]
    # drop duplicate observe actions
    seen_obs = False
    final = []
    for a in ordered:
        if a['type'] == 'observe':
            if seen_obs:
                continue
            seen_obs = True
        final.append(a)
    return final


def _install(app, apps):
    info = apps.get(app) or {}
    if not info.get('apk'):
        return _skip('install', app, 'APK not built: %s' % os.path.join(app, APK_REL))
    return {'type': 'install', 'target': app, 'argv': [['install', '-r', '-t', info['apk']]]}


def _launch(app, apps):
    info = apps.get(app) or {}
    pkg, act = info.get('package'), info.get('activity')
    if not pkg:
        return _skip('launch', app, 'package name unknown')
    if act:
        argv = ['shell', 'am', 'start', '-W', '-n', '%s/%s' % (pkg, act)]
    else:
        argv = ['shell', 'monkey', '-p', pkg, '-c', 'android.intent.category.LAUNCHER', '1']
    return {'type': 'launch', 'target': app, 'package': pkg, 'argv': [argv]}


def _summary(action):
    st = action.get('status', '')
    if st.startswith('skipped'):
        return '%s %s (%s)' % (action['type'], action.get('target'), st)
    t = action['type']
    if t == 'tap':
        return "tap %r" % action['target']
    return '%s %s' % (t, action.get('target') or '')


# ---------------------------------------------------------------- uiautomator

def parse_bounds(bounds):
    """'[x1,y1][x2,y2]' -> (x1, y1, x2, y2), or None."""
    m = BOUNDS_RE.search(bounds or '')
    return tuple(int(g) for g in m.groups()) if m else None


def bounds_center(bounds):
    """Centre (x, y) of a uiautomator bounds string, or None."""
    b = parse_bounds(bounds)
    if not b:
        return None
    x1, y1, x2, y2 = b
    return (x1 + x2) // 2, (y1 + y2) // 2


def _norm(s):
    return re.sub(r'[\s*"\u201c\u201d]+', ' ', (s or '')).strip().lower()


def find_node(xml_text, label):
    """Best node for `label` in a uiautomator dump: dict of attributes, or None.

    An empty label picks the first clickable Button. Matching on text or
    content-desc, case-insensitive: exact, then prefix, then substring;
    clickable nodes win ties.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    nodes = [n.attrib for n in root.iter('node')]
    want = _norm(label)
    if not want:
        for n in nodes:
            if 'Button' in n.get('class', '') and n.get('clickable') == 'true':
                return n
        for n in nodes:
            if n.get('clickable') == 'true' and n.get('package') != 'com.android.systemui':
                return n
        return None
    best = None
    best_score = 0
    for n in nodes:
        for val in (n.get('text'), n.get('content-desc')):
            v = _norm(val)
            if not v:
                continue
            score = 0
            if v == want:
                score = 30
            elif v.startswith(want) or want.startswith(v):
                score = 20
            elif want in v:
                score = 10
            if score and n.get('clickable') == 'true':
                score += 5
            if score > best_score and parse_bounds(n.get('bounds')):
                best, best_score = n, score
    return best


# ---------------------------------------------------------------- capture

def foreground_activity(dumpsys_text):
    m = FOREGROUND_RE.search(dumpsys_text or '')
    return '%s/%s' % (m.group(1), m.group(2)) if m else None


def classify_logcat(lines):
    sig = {'crashes': [], 'permission_denials': [], 'security_exceptions': [], 'anr': []}
    for i, line in enumerate(lines):
        if CRASH_RE.search(line):
            sig['crashes'].append(line)
        if PERM_RE.search(line):
            sig['permission_denials'].append(line)
        if SECEX_RE.search(line):
            sig['security_exceptions'].append(line)
        if ANR_RE.search(line):
            sig['anr'].append(line)
    return sig


LOG_PID_RE = re.compile(r'^\d\d-\d\d\s+[\d:.]+\s+(\d+)\s+\d+\s+[VDIWEF]\s')
START_PROC_RE = re.compile(r'Start proc (\d+):([\w.]+)')
PROC_PID_RE = re.compile(r'Process: ([\w.]+)(?::\w+)?, PID: (\d+)')


def app_pids(text, packages):
    """PIDs of `packages` announced in logcat (Start proc / crash header)."""
    pids = set()
    pk = set(packages)
    for m in START_PROC_RE.finditer(text or ''):
        if m.group(2) in pk:
            pids.add(int(m.group(1)))
    for m in PROC_PID_RE.finditer(text or ''):
        if m.group(1) in pk:
            pids.add(int(m.group(2)))
    return pids


def relevant_logcat(text, keywords, pids=()):
    """Lines logged by an app process (pid in `pids`) or that mention a keyword
    (app names, package names, README grep strings), case-insensitive."""
    keys = [k.lower() for k in keywords if k]
    pids = set(pids)
    out = []
    for line in (text or '').splitlines():
        line = line.rstrip('\r')
        if not line.strip() or line.startswith('---------'):
            continue
        pm = LOG_PID_RE.match(line)
        if (pm and int(pm.group(1)) in pids) or any(k in line.lower() for k in keys):
            out.append(line)
    return out[-MAX_LOG_LINES:]


# ---------------------------------------------------------------- runner

def _execute(action, adbc, keywords):
    """Run one planned action in place."""
    action['commands'] = []
    action['returncodes'] = []
    action['output'] = []
    if action['type'] == 'tap':
        return _tap(action, adbc)
    if action['type'] == 'observe':
        action['status'] = 'ok'
        return
    ok = True
    for args in action['argv']:
        timeout = INSTALL_TIMEOUT if args and args[0] == 'install' else TIMEOUT
        code, out = adbc.run(args, timeout=timeout)
        action['commands'].append(cmdline(args))
        action['returncodes'].append(code)
        if action.get('grep'):
            out = '\n'.join(l for l in out.splitlines() if action['grep'].lower() in l.lower())
            keywords.append(action['grep'])
        action['output'].append(out.strip()[-2000:])
        failed = code != 0 or re.search(r'^(?:Failure|Error)\b|Exception occurred', out, re.M)
        if action['type'] == 'install' and 'Success' not in out:
            failed = True
        ok = ok and not failed
    action['status'] = 'ok' if ok else 'failed'
    if action['type'] in ('launch',):
        time.sleep(LAUNCH_WAIT)
    elif action['type'] in ('back',):
        time.sleep(TAP_WAIT)


def _tap(action, adbc):
    remote = '/sdcard/ate_ui_dump.xml'
    steps = [['shell', 'uiautomator', 'dump', remote]]
    code, out = adbc.run(steps[0], timeout=TIMEOUT)
    action['commands'].append(cmdline(steps[0]))
    action['returncodes'].append(code)
    fd, local = tempfile.mkstemp(suffix='.xml', prefix='ate_ui_')
    os.close(fd)
    try:
        pull = ['pull', remote, local]
        code2, _ = adbc.run(pull, timeout=TIMEOUT)
        action['commands'].append(cmdline(pull))
        action['returncodes'].append(code2)
        try:
            with open(local, encoding='utf-8', errors='replace') as f:
                xml_text = f.read()
        except OSError:
            xml_text = ''
    finally:
        try:
            os.remove(local)
        except OSError:
            pass
    node = find_node(xml_text, action['target'])
    if node is None:
        action['status'] = 'failed'
        action['output'].append('no node matching %r in UI dump' % action['target'])
        return
    x, y = bounds_center(node.get('bounds'))
    tap = ['shell', 'input', 'tap', str(x), str(y)]
    code3, out3 = adbc.run(tap, timeout=TIMEOUT)
    action['commands'].append(cmdline(tap))
    action['returncodes'].append(code3)
    action['output'].append('tapped %r (%s) at %d,%d' % (
        node.get('text') or node.get('content-desc'), node.get('resource-id', ''), x, y))
    action['status'] = 'ok' if code3 == 0 else 'failed'
    time.sleep(TAP_WAIT)


def _planned_commands(action):
    if action['type'] == 'tap':
        return ['adb shell uiautomator dump /sdcard/ate_ui_dump.xml',
                'adb pull /sdcard/ate_ui_dump.xml <tmp>',
                'adb shell input tap <centre of %r>' % action['target']]
    return [cmdline(a) for a in action.get('argv', [])]


def run_readme(readme_path, adb='adb', device=None, dry_run=False, settle=3.0):
    """Parse, plan and (unless dry_run) replay a Ghera README. See module doc.

    settle: seconds to wait after a step's actions before capturing logcat.
    """
    try:
        with open(readme_path, encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError as e:
        log.warning('cannot read %s: %s', readme_path, e)
        return []
    bench_dir = os.path.dirname(os.path.abspath(readme_path))
    apps = bench_apps(bench_dir)
    steps = parse_steps(text)
    plans = [(s, plan_step(s, apps, bench_dir)) for s in steps]

    adbc = None
    no_device = None
    if not dry_run:
        path = resolve_adb(adb)
        if not path:
            no_device = 'adb not found'
        else:
            adbc = Adb(path, device)
            if not adbc.available():
                no_device = 'no device'
                adbc = None
    packages = [a['package'] for a in apps.values() if a.get('package')]
    keywords = list(apps) + packages
    pids = set()

    if adbc:
        adbc.run(['logcat', '-c'])

    observations = []
    for step, actions in plans:
        for a in actions:
            a.setdefault('status', 'planned')
        runnable = [a for a in actions if not a['status'].startswith('skipped')]
        obs = {'step': step['step'], 'index': step['index'], 'text': step['text'],
               'actions': actions, 'commands': [], 'returncodes': [], 'logcat': [],
               'signals': classify_logcat([]), 'foreground_activity': None,
               'automatable': bool(runnable)}
        if not actions:
            obs['action'] = 'skipped: no automatable action'
        elif not runnable:
            obs['action'] = 'skipped: ' + '; '.join(_summary(a) for a in actions)
        elif no_device:
            obs['action'] = 'skipped: %s' % no_device
            for a in runnable:
                a['status'] = 'skipped: ' + no_device
            obs['commands'] = [c for a in runnable for c in _planned_commands(a)]
        elif dry_run:
            obs['action'] = '; '.join(_summary(a) for a in actions)
            obs['commands'] = [c for a in runnable for c in _planned_commands(a)]
        else:
            for a in runnable:
                _execute(a, adbc, keywords)
                obs['commands'] += a['commands']
                obs['returncodes'] += a['returncodes']
            obs['action'] = '; '.join(
                _summary(a) + ('' if a['status'] in ('ok', 'planned') or
                               a['status'].startswith('skipped') else ' [%s]' % a['status'])
                for a in actions)
        for a in actions:
            a.pop('argv', None)
        if adbc and runnable:
            time.sleep(settle)
            for pkg in packages:
                code, out = adbc.run(['shell', 'pidof', pkg], timeout=15)
                pids.update(int(p) for p in out.split() if p.isdigit())
            _, logtxt = adbc.run(['logcat', '-d', '-v', 'threadtime'], timeout=60)
            adbc.run(['logcat', '-c'])
            pids |= app_pids(logtxt, packages)
            obs['logcat'] = relevant_logcat(logtxt, keywords, pids)
            obs['signals'] = classify_logcat(obs['logcat'])
            _, dump = adbc.run(['shell', 'dumpsys', 'activity', 'activities'], timeout=TIMEOUT)
            obs['foreground_activity'] = foreground_activity(dump)
        observations.append(obs)
    return observations


# ---------------------------------------------------------------- CLI

def expand_readmes(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            own = os.path.join(p, 'README.md')
            subs = sorted(glob.glob(os.path.join(p, '*', '*', 'README.md')))
            if subs:
                out += subs
            elif os.path.exists(own):
                out.append(own)
            else:
                out += sorted(glob.glob(os.path.join(p, '*', 'README.md')))
        else:
            out.append(p)
    return out


def coverage(results):
    """Summary over {readme: observations}."""
    n_parsed = sum(1 for o in results.values() if o)
    steps = [s for o in results.values() for s in o]
    auto = [s for s in steps if s['automatable']]
    setup = [s for s in steps if s['actions'] and all(a['type'] == 'setup' for a in s['actions'])]
    non_setup = len(steps) - len(setup)
    by_type = {}
    for s in steps:
        for a in s['actions']:
            key = a['type'] + (' (skipped)' if a['status'].startswith('skipped') else '')
            by_type[key] = by_type.get(key, 0) + 1
    return {'readmes': len(results), 'with_steps': n_parsed, 'steps': len(steps),
            'automatable_steps': len(auto),
            'automatable_fraction': round(len(auto) / len(steps), 3) if steps else 0.0,
            'emulator_setup_steps': len(setup),
            'automatable_fraction_excl_setup':
                round(len(auto) / non_setup, 3) if non_setup else 0.0,
            'actions': dict(sorted(by_type.items()))}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('readme', nargs='+', help='README.md, a benchmark dir, or the ghera dir')
    ap.add_argument('--dry-run', action='store_true', help='parse and plan only')
    ap.add_argument('--json', help='write observations to this file')
    ap.add_argument('--device', help='adb serial')
    ap.add_argument('--adb', default='adb', help='adb executable (default: discover)')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format='%(levelname)s %(message)s')
    readmes = expand_readmes(args.readme)
    results = {}
    for r in readmes:
        results[r] = run_readme(r, adb=args.adb, device=args.device, dry_run=args.dry_run)
        if len(readmes) == 1:
            for o in results[r]:
                print('%3s. %s' % (o['step'], o['action']))
                if o['foreground_activity']:
                    print('     foreground: %s' % o['foreground_activity'])
                for k, v in o['signals'].items():
                    for line in v[:3]:
                        print('     %s: %s' % (k, line))
    if len(readmes) > 1:
        print(json.dumps(coverage(results), indent=2))
    if args.json:
        payload = results[readmes[0]] if len(readmes) == 1 else \
            {'coverage': coverage(results), 'results': results}
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
    return 0


if __name__ == '__main__':
    sys.exit(main())
