"""Dynamic checks that install an APK on a device or emulator through adb.

run(apk_path, package, main_activity=None, adb=None, wait=3, manifest=None)
returns a list of findings, each a dict with:
  component, component_type, issue, cwe, confidence (high, medium or low), evidence

Steps: install the APK, clear logcat, start the main activity, wait, read
logcat, read the task stack (dumpsys activity activities) and the package's
components (dumpsys package), send an explicit broadcast from the shell to every
exported receiver, diff the app's files/ folder around each broadcast, and
finally uninstall the package, also when a step fails.

run_all(apk_dir, package, main_activity=None, adb=None, wait=3, manifest=None)
does everything run() does and also sweeps every broadcast for side effects.
apk_dir is an APK file or a folder (the first *.apk of a sorted walk is used).
Around each broadcast it records the app's pid, crash lines in logcat (FATAL
EXCEPTION or AndroidRuntime lines of the app process or naming the package),
new activities, new logcat lines, the foreground task (from mResumedActivity,
mFocusedActivity or topResumedActivity in dumpsys activity activities, else the
first task) and the files/ listing, and reports crashes, foreign activities that
appeared in the foreground task and deleted files.

Receivers registered at run time (Context.registerReceiver) are not in the
manifest and cannot be reached by an explicit broadcast. They are read from
dumpsys activity broadcasts for the app's process and probed with a broadcast
of each registered action restricted to the package (am broadcast -a ... -p ...).

Issues (ISSUES maps each to its CWE):
  dynamic-receiver-accepts-external    a receiver ran a broadcast sent by the
                                       shell user, with no Permission Denial.
                                       CWE-926 when the receiver has no
                                       permission, else CWE-925
  dynamic-file-created                 a new file appeared in files/ after the
                                       broadcasts
  dynamic-task-hijack                  an activity of another package sits in
                                       the same task as the app's activities, or
                                       a task of another package holds the app's
                                       affinity
  dynamic-permission-denial-observed   logcat shows a Permission Denial that
                                       names the package (no CWE: the platform
                                       blocked the call)

Issues reported only by run_all:
  dynamic-receiver-crash               the app crashed after a broadcast: a
                                       FATAL EXCEPTION in logcat, or its process
                                       died or was restarted (CWE-248)
  dynamic-foreground-foreign-activity  an activity of another package appeared
                                       in the foreground task after a broadcast
                                       (CWE-1021)
  dynamic-file-deleted                 a file in files/ disappeared after a
                                       broadcast (CWE-922)

Without adb or a device run() and run_all() log a warning and return []. Device and adb
failures are logged, never raised. adb honours ANDROID_SERIAL when more than one
device is attached.

Also usable from the command line:
  python src/dynamic_analyzer.py <apk> <package> [main_activity]
"""
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time

log = logging.getLogger(__name__)

ISSUES = {
    'dynamic-receiver-accepts-external': 'CWE-925',
    'dynamic-file-created': 'CWE-922',
    'dynamic-task-hijack': 'CWE-1021',
    'dynamic-permission-denial-observed': 'n/a',
    'dynamic-receiver-crash': 'CWE-248',
    'dynamic-foreground-foreign-activity': 'CWE-1021',
    'dynamic-file-deleted': 'CWE-922',
}
CWE_RECEIVER_NO_PERMISSION = 'CWE-926'
DEFAULT_ADB = r'C:\Android\Sdk\platform-tools\adb.exe'
TIMEOUT = 30
INSTALL_TIMEOUT = 180

# threadtime logcat line: date time pid tid level tag: message
LOGCAT_RE = re.compile(r'^\d\d-\d\d\s+[\d:.]+\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+(.*?)\s*:\s?(.*)$')
TASK_RE = re.compile(r'^\s*\*?\s*(?:TaskRecord|Task)\{[0-9a-f]+ #(\d+)(?: type=\S+)? ([AI])=(\S+)')
TASK_AFFINITY_RE = re.compile(r'^\s*affinity=(\S+)')
HIST_RE = re.compile(r'\* Hist #\d+: ActivityRecord\{[0-9a-f]+ u\d+ ([\w.$]+)/([\w.$]+) t(\d+)')
RUN_RE = re.compile(r'Run #\d+: ActivityRecord\{[0-9a-f]+ u\d+ ([\w.$]+)/([\w.$]+) t(\d+)')
ACT_AFFINITY_RE = re.compile(r'^\s*taskAffinity=(\S+)')
RESOLVER_RE = re.compile(r'^\s+[0-9a-f]+ ([\w.$]+)/([\w.$]+)(?: filter [0-9a-f]+)?\s*$')
FOREGROUND_RE = re.compile(
    r'(?:mResumedActivity|mFocusedActivity|topResumedActivity|ResumedActivity)[:=]\s*'
    r'ActivityRecord\{[0-9a-f]+ u\d+ ([\w.$]+)/([\w.$]+) t(\d+)')
CRASH_PROCESS_RE = re.compile(r'Process: ([\w.:]+), PID: (\d+)')
BROADCAST_RESULT_RE =re.compile(r'Broadcast completed: result=(-?\d+)')

RESOLVER_TABLES = {
    'Activity Resolver Table:': 'activity',
    'Receiver Resolver Table:': 'receiver',
    'Service Resolver Table:': 'service',
    'Provider Resolver Table:': 'provider',
}


# adb plumbing

def find_adb():
    """Path to adb: PATH, then ANDROID_HOME, then the default SDK folder."""
    found = shutil.which('adb')
    if found:
        return found
    exe = 'adb.exe' if os.name == 'nt' else 'adb'
    home = os.environ.get('ANDROID_HOME')
    if home:
        cand = os.path.join(home, 'platform-tools', exe)
        if os.path.exists(cand):
            return cand
    if os.path.exists(DEFAULT_ADB):
        return DEFAULT_ADB
    return None


def _adb(adb, args, timeout=TIMEOUT):
    """Run adb with `args`; return (exit code, stdout + stderr). Never raises."""
    try:
        r = subprocess.run([adb] + list(args), capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=timeout)
        return r.returncode, (r.stdout or '') + (r.stderr or '')
    except subprocess.TimeoutExpired:
        log.warning('adb %s timed out after %ss', ' '.join(args), timeout)
        return -1, ''
    except OSError as e:
        log.warning('adb %s failed: %s', ' '.join(args), e)
        return -1, ''


def _shell(adb, *args, timeout=TIMEOUT):
    return _adb(adb, ('shell',) + args, timeout)[1]


def device_available(adb=None):
    """True when 'adb devices' lists at least one device in the 'device' state."""
    adb = adb or find_adb()
    if not adb:
        return False
    code, out = _adb(adb, ['devices'], timeout=15)
    if code != 0:
        return False
    return any(line.rstrip('\r').endswith('\tdevice') for line in out.splitlines()[1:])


# parsers

def parse_logcat(text):
    """[{pid, tid, level, tag, message, line}] from threadtime logcat output."""
    lines = []
    for raw in text.splitlines():
        m = LOGCAT_RE.match(raw.rstrip('\r'))
        if m:
            lines.append({'pid': int(m.group(1)), 'tid': int(m.group(2)), 'level': m.group(3),
                          'tag': m.group(4), 'message': m.group(5), 'line': raw.rstrip('\r')})
    return lines


def parse_activities(text):
    """Tasks and activities from 'dumpsys activity activities'.

    Returns {'tasks': [{id, affinity, activities}], 'activities': [...]} where each
    activity is {component, package, task_id, task_affinity}.
    """
    tasks = {}
    order = []
    current = None
    last_act = None

    def task(tid):
        if tid not in tasks:
            tasks[tid] = {'id': tid, 'affinity': None, 'activities': []}
            order.append(tid)
        return tasks[tid]

    for raw in text.splitlines():
        line = raw.rstrip('\r')
        m = TASK_RE.match(line)
        if m:
            current = task(int(m.group(1)))
            if m.group(2) == 'A' and current['affinity'] is None:
                # newer releases print A=<uid>:<affinity>
                current['affinity'] = re.sub(r'^\d+:', '', m.group(3))
            last_act = None
            continue
        m = TASK_AFFINITY_RE.match(line)
        if m and current is not None and last_act is None:
            current['affinity'] = m.group(1)
            continue
        m = HIST_RE.search(line) or RUN_RE.search(line)
        if m:
            pkg, cls, tid = m.group(1), m.group(2), int(m.group(3))
            comp = pkg + '/' + cls
            t = task(tid)
            existing = [a for a in t['activities'] if a['component'] == comp]
            if existing:
                last_act = existing[0] if 'Hist #' in line else None
                continue
            act = {'component': comp, 'package': pkg, 'task_id': tid, 'task_affinity': None}
            t['activities'].append(act)
            last_act = act if 'Hist #' in line else None
            continue
        m = ACT_AFFINITY_RE.match(line)
        if m and last_act is not None:
            last_act['task_affinity'] = None if m.group(1) == 'null' else m.group(1)
    task_list = [tasks[t] for t in order]
    return {'tasks': task_list, 'activities': [a for t in task_list for a in t['activities']]}


def _full_name(package, cls):
    return package + cls if cls.startswith('.') else cls


def parse_package(text, package):
    """Components of `package` from 'dumpsys package <package>'.

    Returns {'components': [{name, type, exported}]}. exported is True or False
    when dumpsys prints the flag (newer releases), else None. A component listed
    in a resolver table has an intent filter.
    """
    found = {}
    table = None
    for raw in text.splitlines():
        line = raw.rstrip('\r')
        stripped = line.strip()
        if stripped in RESOLVER_TABLES and not line.startswith(' ' * 4):
            table = RESOLVER_TABLES[stripped]
            continue
        if line and not line.startswith(' '):
            table = None
            continue
        if table:
            m = RESOLVER_RE.match(line)
            if m and m.group(1) == package:
                name = _full_name(package, m.group(2))
                found.setdefault(name, {'name': name, 'type': table, 'exported': None})
    # exported=true/false appears next to component names in some releases
    for m in re.finditer(r'([\w.$]+)/([\w.$]+)[^\n]*?\bexported=(true|false)', text):
        if m.group(1) == package:
            name = _full_name(package, m.group(2))
            if name in found:
                found[name]['exported'] = m.group(3) == 'true'
    return {'components': list(found.values())}


def parse_registered_receivers(text, pid):
    """Receivers registered at run time by process `pid`, from 'dumpsys activity
    broadcasts': [{actions, permission}]."""
    receivers = []
    current = None
    in_list = False
    for raw in text.splitlines():
        line = raw.rstrip('\r')
        m = re.match(r'^\s*\* ReceiverList\{[0-9a-f]+ (\d+) ', line)
        if m:
            in_list = int(m.group(1)) == pid
            current = None
            continue
        if not in_list:
            continue
        if re.match(r'^\s*Filter #\d+: BroadcastFilter', line):
            current = {'actions': [], 'permission': None}
            receivers.append(current)
            continue
        if current is None:
            continue
        m = re.match(r'^\s*Action: "([^"]+)"', line)
        if m:
            current['actions'].append(m.group(1))
            continue
        m = re.match(r'^\s*requiredPermission=(\S+)', line)
        if m:
            current['permission'] = m.group(1)
            continue
        if not line.startswith(' ' * 4):
            in_list = False
    return [r for r in receivers if r['actions']]


def parse_foreground_task(text):
    """Foreground task of 'dumpsys activity activities'.

    Returns {'id', 'activities'} where activities are the components in that
    task. The task id comes from the mResumedActivity, mFocusedActivity or
    topResumedActivity line; without one the first task is used. Returns
    {'id': None, 'activities': []} when no task is listed.
    """
    stack = parse_activities(text)
    tid = None
    for raw in text.splitlines():
        m = FOREGROUND_RE.search(raw)
        if m:
            tid = int(m.group(3))
            break
    if tid is None and stack['tasks']:
        tid = stack['tasks'][0]['id']
    task = {t['id']: t for t in stack['tasks']}.get(tid)
    return {'id': tid, 'activities': [a['component'] for a in task['activities']] if task else []}


def crash_lines(lines, package, pids=()):
    """Logcat lines (from parse_logcat) that show `package` crashing.

    A crash is a FATAL EXCEPTION or AndroidRuntime error line written by one of
    `pids`, or by the pid named in an AndroidRuntime "Process: <package>, PID: n"
    line. Returns the raw lines, or [] when there is no FATAL EXCEPTION.
    """
    pids = {p for p in pids if p}
    for l in lines:
        m = CRASH_PROCESS_RE.search(l['message'])
        if l['tag'] == 'AndroidRuntime' and m and m.group(1).split(':')[0] == package:
            pids.add(int(m.group(2)))
    found = [l for l in lines if l['pid'] in pids and l['level'] in 'EF'
             and (l['tag'] == 'AndroidRuntime' or 'FATAL EXCEPTION' in l['message'])]
    if not any('FATAL EXCEPTION' in l['message'] for l in found):
        return []
    return [l['line'] for l in found]


# device helpers

def _pid(adb, package):
    out = _shell(adb, 'pidof', package).strip()
    if out.split() and out.split()[0].isdigit():
        return int(out.split()[0])
    for line in _shell(adb, 'ps', '-A').splitlines() or _shell(adb, 'ps').splitlines():
        cols = line.split()
        if cols and cols[-1] == package and len(cols) > 1 and cols[1].isdigit():
            return int(cols[1])
    return None


def _resolve_main_activity(adb, package):
    out = _shell(adb, 'cmd', 'package', 'resolve-activity', '--brief', package)
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith(package + '/'):
            return line.split('/', 1)[1]
    # Fall back to the MAIN entries of the activity resolver table.
    out = _shell(adb, 'dumpsys', 'package', package)
    in_main = False
    for line in out.splitlines():
        s = line.strip()
        if s.endswith(':') and '.' in s:
            in_main = s == 'android.intent.action.MAIN:'
            continue
        m = RESOLVER_RE.match(line)
        if in_main and m and m.group(1) == package:
            return m.group(2)
    return None


def _list_files(adb, package):
    """Names in the app's files/ folder, or None when run-as cannot read it."""
    code, out = _adb(adb, ['shell', 'run-as', package, 'ls', 'files/'])
    if 'No such file or directory' in out:
        return set()
    if code != 0 or 'run-as:' in out:
        return None
    return {n.strip() for n in out.split() if n.strip()}


def _logcat(adb, count=200):
    return _adb(adb, ['logcat', '-d', '-v', 'threadtime', '-t', str(count)])[1]


def _finding(component, component_type, issue, confidence, evidence, cwe=None):
    return {
        'component': component,
        'component_type': component_type,
        'issue': issue,
        'cwe': cwe or ISSUES[issue],
        'confidence': confidence,
        'evidence': evidence,
    }


def _app_lines(lines, package, pids):
    """Logcat lines written by the app process or naming the package."""
    return [l for l in lines if l['pid'] in pids or package in l['message']]


def _denials(lines, package):
    return [l['line'] for l in lines if 'Permission Denial' in l['message'] and package in l['message']]


def _exported_receivers(manifest, pkg_info):
    """[{name, permission}] of receivers reachable by an explicit broadcast."""
    if manifest and manifest.get('components'):
        return [{'name': c['name'], 'permission': c.get('permission')}
                for c in manifest['components']
                if c['type'] == 'receiver' and c.get('exported')]
    # Without a manifest: receivers in the resolver table, unless dumpsys says
    # exported=false. Their permission is unknown.
    return [{'name': c['name'], 'permission': None}
            for c in pkg_info['components']
            if c['type'] == 'receiver' and c['exported'] is not False]


def _task_hijack(stack, package):
    findings = []
    for t in stack['tasks']:
        own = [a for a in t['activities'] if a['package'] == package]
        foreign = [a for a in t['activities'] if a['package'] != package]
        if own and foreign:
            for a in own:
                findings.append(_finding(
                    _full_name(package, a['component'].split('/', 1)[1]), 'activity',
                    'dynamic-task-hijack', 'high',
                    'task #%d (affinity %s) also holds %s' % (
                        t['id'], t['affinity'], ', '.join(f['component'] for f in foreign))))
        elif foreign and not own and t['affinity'] == package:
            findings.append(_finding(
                package, 'application', 'dynamic-task-hijack', 'medium',
                'task #%d of %s has the affinity %s of this app' % (
                    t['id'], ', '.join(f['component'] for f in foreign), package)))
    return findings


def _probe(adb, package, args, deny_markers):
    """Send one broadcast from the shell and collect what happened."""
    before_files = _list_files(adb, package)
    before_text = _shell(adb, 'dumpsys', 'activity', 'activities')
    before_stack = parse_activities(before_text)
    pid = _pid(adb, package)
    _adb(adb, ['logcat', '-c'])
    out = _shell(adb, 'am', 'broadcast', *args)
    time.sleep(1)
    lines = parse_logcat(_logcat(adb, 400))
    pid_after = _pid(adb, package)
    pids = {p for p in (pid, pid_after) if p}
    after_text = _shell(adb, 'dumpsys', 'activity', 'activities')
    after_stack = parse_activities(after_text)
    after_files = _list_files(adb, package)
    m = BROADCAST_RESULT_RE.search(out)
    old = {a['component'] for a in before_stack['activities']}
    old_placed = {(a['component'], a['task_id']) for a in before_stack['activities']}
    fg_after = parse_foreground_task(after_text)
    crashes = crash_lines(lines, package, pids)
    return {
        'output': out.strip(),
        'completed': m is not None,
        'result': int(m.group(1)) if m else None,
        'lines': lines,
        'app_lines': [l for l in _app_lines(lines, package, pids)
                      if 'Permission Denial' not in l['message']],
        'denials': [d for d in _denials(lines, package) if any(k in d for k in deny_markers)],
        'new_activities': [a['component'] for a in after_stack['activities']
                           if a['package'] == package and a['component'] not in old],
        'stack': after_stack,
        'new_files': sorted(after_files - before_files) if None not in (before_files, after_files) else [],
        'removed_files': sorted(before_files - after_files) if None not in (before_files, after_files) else [],
        'pid_before': pid,
        'pid_after': pid_after,
        'crash_lines': crashes,
        'crashed': bool(crashes) or (pid is not None and pid_after != pid),
        'foreground_before': parse_foreground_task(before_text),
        'foreground_after': fg_after,
        'foreign_foreground': [c for c in fg_after['activities']
                               if c.split('/', 1)[0] != package
                               and (c, fg_after['id']) not in old_placed],
    }


def _receiver_finding(name, ctype, permission, probe):
    if not probe['completed'] or probe['denials']:
        return None
    signs = []
    if probe['new_activities']:
        signs.append('started ' + ', '.join(probe['new_activities']))
    if probe['result'] not in (None, 0):
        signs.append('result code %d' % probe['result'])
    if probe['app_lines']:
        signs.append('%d new logcat line(s) from the app, e.g. %s' % (
            len(probe['app_lines']), probe['app_lines'][-1]['line']))
    if probe['removed_files']:
        signs.append('removed files/' + ', files/'.join(probe['removed_files']))
    confidence = 'high' if signs else 'medium'
    evidence = '; '.join([probe['output'].splitlines()[-1]] + signs)
    cwe = None if permission else CWE_RECEIVER_NO_PERMISSION
    return _finding(name, ctype, 'dynamic-receiver-accepts-external', confidence, evidence, cwe)


def _sweep_findings(name, ctype, p, seen_deleted):
    """run_all findings for one broadcast: crash, foreign activity in the
    foreground task, deleted files."""
    findings = []
    if p['crashed']:
        if p['crash_lines']:
            evidence = 'crash after the broadcast: ' + ' | '.join(p['crash_lines'][:3])
            confidence = 'high'
        else:
            evidence = 'app process %s before the broadcast, %s after' % (
                p['pid_before'], p['pid_after'] or 'gone')
            confidence = 'medium'
        findings.append(_finding(name, ctype, 'dynamic-receiver-crash', confidence, evidence))
    for comp in p['foreign_foreground']:
        findings.append(_finding(
            name, ctype, 'dynamic-foreground-foreign-activity', 'high',
            '%s appeared in the foreground task #%s after the broadcast' % (
                comp, p['foreground_after']['id'])))
    for fn in p['removed_files']:
        if fn not in seen_deleted:
            seen_deleted.add(fn)
            findings.append(_finding(name, ctype, 'dynamic-file-deleted', 'high',
                                     'files/%s disappeared after the broadcast' % fn))
    return findings


def _find_apk(apk_dir):
    """`apk_dir` when it is not a folder, else the first *.apk of a sorted walk."""
    if not os.path.isdir(apk_dir):
        return apk_dir
    for root, dirs, files in os.walk(apk_dir):
        dirs.sort()
        for fn in sorted(files):
            if fn.lower().endswith('.apk'):
                return os.path.join(root, fn)
    return None


def run(apk_path, package, main_activity=None, adb=None, wait=3, manifest=None):
    """Install `apk_path`, exercise it, uninstall it and return the findings.

    `manifest` is the dict apk.decode() returns; it tells which receivers are
    exported and protected, since dumpsys on API 27 does not print the flag.
    """
    return _run(apk_path, package, main_activity, adb, wait, manifest, sweep=False)


def run_all(apk_dir, package, main_activity=None, adb=None, wait=3, manifest=None):
    """run() plus a per-broadcast sweep for crashes, foreign activities in the
    foreground task and deleted files.

    `apk_dir` is an APK file or a folder; for a folder the first *.apk found by
    a sorted walk is installed. Never raises; the package is always uninstalled.
    """
    apk_path = _find_apk(apk_dir)
    if not apk_path:
        log.warning('no .apk found under %s; skipping dynamic analysis', apk_dir)
        return []
    return _run(apk_path, package, main_activity, adb, wait, manifest, sweep=True)


def _run(apk_path, package, main_activity=None, adb=None, wait=3, manifest=None, sweep=False):
    """Shared body of run() and run_all(); `sweep` adds the run_all findings."""
    adb = adb or find_adb()
    if not adb:
        log.warning('adb not found; skipping dynamic analysis')
        return []
    if not device_available(adb):
        log.warning('no adb device in the "device" state; skipping dynamic analysis')
        return []

    findings = []
    denial_lines = []
    try:
        code, out = _adb(adb, ['install', '-r', apk_path], timeout=INSTALL_TIMEOUT)
        if code != 0 or 'Success' not in out:
            log.warning('install of %s failed: %s', apk_path, out.strip())
            return []

        main_activity = main_activity or _resolve_main_activity(adb, package)
        _adb(adb, ['logcat', '-c'])
        if main_activity:
            target = main_activity if '/' in main_activity else package + '/' + main_activity
            _shell(adb, 'am', 'start', '-n', target)
        else:
            log.warning('no main activity found for %s; not starting it', package)
        time.sleep(wait)

        baseline = parse_logcat(_logcat(adb, 200))
        denial_lines += _denials(baseline, package)

        stack = parse_activities(_shell(adb, 'dumpsys', 'activity', 'activities'))
        findings += _task_hijack(stack, package)

        pkg_info = parse_package(_shell(adb, 'dumpsys', 'package', package), package)
        start_files = _list_files(adb, package)
        seen_files = set(start_files or ())
        seen_deleted = set()

        probes = []
        for rec in _exported_receivers(manifest, pkg_info):
            short = rec['name'][len(package):] if rec['name'].startswith(package + '.') else rec['name']
            p = _probe(adb, package, ['-n', package + '/' + rec['name']],
                       (rec['name'], package + '/' + short))
            probes.append((rec['name'], 'receiver', rec['permission'], p))

        pid = _pid(adb, package)
        if pid:
            text = _shell(adb, 'dumpsys', 'activity', 'broadcasts')
            for rec in parse_registered_receivers(text, pid):
                for action in rec['actions']:
                    p = _probe(adb, package, ['-a', action, '-p', package], ('registered receiver',))
                    probes.append(('%s (registered for %s)' % (package, action),
                                   'dynamic-receiver', rec['permission'], p))

        for name, ctype, permission, p in probes:
            denial_lines += p['denials'] + _denials(p['lines'], package)
            f = _receiver_finding(name, ctype, permission, p)
            if f:
                findings.append(f)
            for fn in p['new_files']:
                if fn not in seen_files:
                    seen_files.add(fn)
                    findings.append(_finding(name, ctype, 'dynamic-file-created', 'high',
                                             'files/%s appeared after the broadcast' % fn))
            findings += [f for f in _task_hijack(p['stack'], package) if f not in findings]
            if sweep:
                log.info('broadcast to %s: crashed=%s, new activities=%s, new app log lines=%d',
                         name, p['crashed'], p['new_activities'], len(p['app_lines']))
                findings += _sweep_findings(name, ctype, p, seen_deleted)

        end_files = _list_files(adb, package)
        if start_files is not None and end_files is not None:
            for fn in sorted(end_files - start_files - seen_files):
                findings.append(_finding('(application)', 'application', 'dynamic-file-created',
                                         'medium', 'files/%s appeared during the run' % fn))
            if sweep:
                for fn in sorted(start_files - end_files - seen_deleted):
                    findings.append(_finding('(application)', 'application', 'dynamic-file-deleted',
                                             'medium', 'files/%s disappeared during the run' % fn))
        elif start_files is None:
            log.warning('run-as cannot read files/ of %s (not debuggable?); no file diff', package)

        for line in dict.fromkeys(denial_lines):
            m = re.search(r'due to receiver ([\w.$]+/[\w.$]+)', line)
            if m:
                comp, ctype = _full_name(package, m.group(1).split('/', 1)[1]), 'receiver'
            elif 'registered receiver' in line:
                comp, ctype = package + ' (registered receiver)', 'dynamic-receiver'
            else:
                comp, ctype = '(application)', 'application'
            findings.append(_finding(comp, ctype, 'dynamic-permission-denial-observed', 'high', line))
    except Exception as e:  # device problems must not stop the pipeline
        log.warning('dynamic analysis of %s stopped: %s', package, e)
    finally:
        code, out = _adb(adb, ['uninstall', package], timeout=60)
        if code != 0:
            log.warning('uninstall of %s failed: %s', package, out.strip())
    return findings


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    if len(sys.argv) not in (3, 4):
        sys.exit('usage: python src/dynamic_analyzer.py <apk> <package> [main_activity]')
    print(json.dumps(run(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None), indent=2))
