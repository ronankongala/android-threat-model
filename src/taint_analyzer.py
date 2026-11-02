"""Taint flows from untrusted input to dangerous calls, read from smali code.

analyze(decoded_dir, graph=None, skip_libs=True) returns a list of findings,
each a dict with:
  component       dotted class name of the method holding the sink
  component_type  'class'
  issue           'taint-flow'
  pattern         'taint:<source>-><sink>', e.g. 'taint:getStringExtra->rawQuery'
  cwe             CWE of the sink (see SINKS)
  confidence      high (source and sink in one method), medium (through one
                  call), low (through two or more)
  file, line      smali file (relative to decoded_dir) and line of the sink
  evidence        'source L<n>: <line> | sink L<m>: <line>'
  source_line, sink_line   ints

graph is the (graph, reverse) pair or the graph dict from call_graph.build();
it is built when not given. Its keys are the app methods that taint may enter.

Each method body is read top to bottom (branches are not followed) and a set of
tainted registers is kept; taint then follows calls into other app methods (see
Interprocedural below).

Sources (return value is tainted; see _source):
  Intent getStringExtra, getIntExtra, getByteArrayExtra, getAction, getData,
  Bundle getString, Cursor get* on a cursor returned by ContentResolver.query,
  EditText/TextView getText.

Propagation:
  move-result* after a source taints its register; move vA, vB copies taint;
  StringBuilder append (taints the builder too) and toString, String concat,
  valueOf and toString, Uri getPath and getLastPathSegment, Uri.parse,
  <init> of Intent, File, String or StringBuilder with a tainted argument,
  putExtra / putExtras / setData on an Intent with a tainted value (taints the
  Intent), and Intent builder calls on a tainted Intent. aget from a tainted
  array is tainted. const*, new-instance, new-array, field reads and other
  writes of an untainted value clear the register.

Sanitizers stop a flow: if-eqz / if-nez on a tainted register (null check),
equals / equalsIgnoreCase taking a tainted register (every register carrying
the same source value is cleared), and a sink inside a :try_start/:try_end
range is not reported.

Interprocedural: when a tainted register is passed to an app method, the
matching parameter register of the callee is tainted and the callee is
analyzed in turn, up to MAX_DEPTH calls deep, using the call graph built by
call_graph.py to tell app methods from framework ones. When the callee returns
a tainted register, the caller's move-result receives that taint. Confidence is
high for a flow inside one method and drops one step for each call level it
crosses. Argument i of the invoke
register list maps to p<i> of the callee: p0 is 'this' for a non-static
method, and a wide (J or D) argument fills two registers in both the invoke
list and the parameter list, so positions line up. p<n> is v<locals + n>.

Class hierarchy: a map from each app class to its subclasses is built from the
.super and .implements declarations. When a tainted register is passed to an
invoke-virtual or invoke-interface call whose owner type is an app class, the
overrides of that method in subclasses (or implementing classes) up to
MAX_HIERARCHY levels below the owner are analyzed too, with the same argument
taint and the same depth limit and confidence step as the resolved callee.
invoke-super is not followed this way, since it never dispatches to a subclass.

Inter-component flows: the components and their intent-filter actions are read
from the decoded AndroidManifest.xml, and receivers registered in code with
registerReceiver(receiver, IntentFilter) are added by action. Each method body
also tracks constant strings and classes, so that an Intent built with
new Intent(ctx, Cls.class), setClass, setClassName, setComponent or an action
(new Intent(action), setAction) has a known target. When an Intent tainted by
putExtra / putExtras (or a Bundle filled by put*) reaches startActivity,
startService or sendBroadcast (and their ForResult / ordered variants), the
target component is resolved: the explicit class, or else the components of
the matching kind whose intent filters list the action. The receiving
component's entry methods (onCreate, onNewIntent, onStartCommand,
onHandleIntent, onReceive) and their callees are then scanned with every
Intent get*Extra / getExtras call, and Bundle get* on such extras, as a source
labelled 'icc:<getter>'. Confidence drops one step for the component boundary
on top of the steps of the sending flow. A finding whose sink location
(file, line) is already reported is not repeated, so this adds flows that the
plain sources miss (other extra types, Bundle extras) in receiving components,
exported or not. Its evidence starts with
'icc <Sender>.<method> L<n> (<sink>) -> <Receiver> | '. Taint can cross up to
MAX_ICC component boundaries in a chain.
"""

import os

import call_graph as cg

try:
    import apk as _apk
except ImportError:      # pragma: no cover
    _apk = None

# Sink label -> CWE.
#   rawQuery, execSQL      SQL built from input (CWE-89, SQL injection)
#   openFileOutput, File   file path built from input (CWE-22, path traversal)
#   sendBroadcast          input forwarded in an implicit broadcast that other
#                          apps can receive (CWE-927)
#   startActivity,         input forwarded to another component, which acts
#   startService           with this app's privileges (CWE-926). A
#                          startActivity whose Intent is known to carry only an
#                          action (no class, component or package) reports
#                          CWE-927 instead: any app's activity with a matching
#                          intent filter (and a higher priority) can receive it
#   sendTextMessage        input sent off the device by SMS; CWE-200 (exposure
#                          of information to an unauthorized actor) since the
#                          message text or number carries data outside the app
SINKS = {
    'rawQuery': 'CWE-89',
    'execSQL': 'CWE-89',
    'openFileOutput': 'CWE-22',
    'File.<init>': 'CWE-22',
    'sendBroadcast': 'CWE-927',
    'sendTextMessage': 'CWE-200',
    'startActivity': 'CWE-926',
    'startService': 'CWE-926',
}

# Method names matched for each sink. Names are matched on any class, since
# apps call them through their own Activity or Context subclasses.
_SINK_NAMES = {
    'rawQuery': ('rawQuery', 'rawQueryWithFactory'),
    'execSQL': ('execSQL',),
    'openFileOutput': ('openFileOutput',),
    'sendBroadcast': ('sendBroadcast', 'sendBroadcastAsUser',
                      'sendOrderedBroadcast', 'sendStickyBroadcast'),
    'sendTextMessage': ('sendTextMessage', 'sendMultipartTextMessage'),
    'startActivity': ('startActivity', 'startActivityForResult',
                      'startActivityIfNeeded'),
    'startService': ('startService', 'startForegroundService'),
}
_SINK_BY_NAME = {n: label for label, names in _SINK_NAMES.items() for n in names}

INTENT = 'Landroid/content/Intent;'
SB = 'Ljava/lang/StringBuilder;'
STRING = 'Ljava/lang/String;'
URI = 'Landroid/net/Uri;'

_INTENT_SOURCES = ('getStringExtra', 'getIntExtra', 'getByteArrayExtra',
                   'getAction', 'getData')
_BUNDLES = ('Landroid/os/Bundle;', 'Landroid/os/BaseBundle;')
_CURSORS = ('Landroid/database/Cursor;', 'Landroid/database/AbstractCursor;',
            'Landroid/database/sqlite/SQLiteCursor;')
_INIT_CLASSES = (INTENT, 'Ljava/io/File;', STRING, SB)
_PASS = {
    (SB, 'toString'), (STRING, 'concat'), (STRING, 'valueOf'),
    (STRING, 'toString'), (STRING, 'trim'), (STRING, 'toLowerCase'),
    (STRING, 'toUpperCase'), (STRING, 'substring'), (STRING, 'getBytes'),
    (URI, 'getPath'), (URI, 'getLastPathSegment'), (URI, 'parse'),
    (URI, 'toString'), (URI, 'getQueryParameter'),
}
_INTENT_PUTS = ('putExtra', 'putExtras', 'setData', 'setDataAndType',
                'putStringArrayListExtra', 'putIntegerArrayListExtra',
                'putParcelableArrayListExtra',
                'putCharSequenceArrayListExtra', 'replaceExtras')
_EQUALS = ('equals', 'equalsIgnoreCase')

_CLEARS = ('const', 'new-instance', 'new-array', 'filled-new-array', 'sget',
           'iget', 'instance-of', 'array-length', 'move-exception', 'cmp',
           'add-', 'sub-', 'mul-', 'div-', 'rem-', 'and-', 'or-', 'xor-',
           'shl-', 'shr-', 'ushr-', 'neg-', 'not-', 'int-to-', 'long-to-',
           'float-to-', 'double-to-')

MAX_DEPTH = 3
MAX_HIERARCHY = 2
MAX_ICC = 2

COMPONENT_NAME = 'Landroid/content/ComponentName;'
INTENT_FILTER = 'Landroid/content/IntentFilter;'
# start/send sink label -> manifest component types an implicit Intent reaches
_ICC_TYPES = {
    'startActivity': ('activity',),
    'startService': ('service',),
    'sendBroadcast': ('receiver',),
}
_ICC_ENTRIES = ('onCreate', 'onNewIntent', 'onStartCommand', 'onHandleIntent',
                'onReceive')
CONFIDENCE = ('high', 'medium', 'low')


def _dotted(cls):
    return cls[1:-1].replace('/', '.') if cls.startswith('L') else cls


def _param_slots(desc, static):
    """Registers taken by the parameters, 'this' included for instance methods."""
    args = desc[1:desc.index(')')]
    slots = 0 if static else 1
    i = 0
    while i < len(args):
        c = args[i]
        if c == '[':
            while args[i] == '[':
                i += 1
            if args[i] == 'L':
                i = args.index(';', i)
            slots += 1
        elif c == 'L':
            i = args.index(';', i)
            slots += 1
        else:
            slots += 2 if c in 'JD' else 1
        i += 1
    return slots


def _locals(method):
    slots = _param_slots(method['desc'], method['static'])
    for _, line in method['body']:
        if line.startswith('.locals'):
            return int(line.split()[1])
        if line.startswith('.registers'):
            return int(line.split()[1]) - slots
    return 0


def _try_ranges(body):
    starts, ranges = {}, []
    for idx, (_, line) in enumerate(body):
        if line.startswith(':try_start_'):
            starts[line[len(':try_start_'):]] = idx
        elif line.startswith(':try_end_'):
            key = line[len(':try_end_'):]
            if key in starts:
                ranges.append((starts[key], idx))
    return ranges


def _sink(cls, name, desc):
    if cls == 'Ljava/io/File;' and name == '<init>':
        return 'File.<init>'
    label = _SINK_BY_NAME.get(name)
    if label in ('sendBroadcast', 'startActivity', 'startService'):
        return label if INTENT in desc else None
    return label


def _source(cls, name, recv, cursors):
    if cls == INTENT and name in _INTENT_SOURCES:
        return name
    if cls in _BUNDLES and name == 'getString':
        return 'Bundle.getString'
    if (cls in _CURSORS and name.startswith('get') and recv is not None
            and recv in cursors):
        return 'Cursor.' + name
    if name == 'getText' and cls.endswith(('EditText;', 'TextView;')):
        return name
    return None


class _Context:
    def __init__(self, methods, app):
        self.methods = methods
        self.app = app
        self.supers = {m['class']: m['super'] for m in methods.values()}
        self.children = {}
        for m in methods.values():
            for parent in [m['super']] + list(m.get('interfaces') or ()):
                if parent:
                    self.children.setdefault(parent, set()).add(m['class'])
        self.locals = {}
        self.visited = {}     # (signature, seeds) -> origin of a tainted return, or None
        self.findings = {}
        self.components = []  # manifest components (see apk.parse_manifest)
        self.dynamic = {}     # action -> classes registered with registerReceiver
        self.icc = None       # (hops, path) while scanning a receiving component
        self.edges = {}       # (receiver class, sender file, line) -> (hops, path)

    def resolve(self, sig):
        if sig in self.app:
            return sig
        cls, name, desc = cg.split_ref(sig)
        seen = set()
        while cls in self.supers and cls not in seen:
            seen.add(cls)
            cls = self.supers[cls]
            cand = '%s->%s%s' % (cls, name, desc)
            if cand in self.app:
                return cand
        return None

    def overrides(self, sig, exclude=None):
        """App methods overriding sig in classes up to MAX_HIERARCHY levels
        below its owner class, nearest first."""
        cls, name, desc = cg.split_ref(sig)
        if cls not in self.supers:
            return []
        out, level, seen = [], [cls], {cls}
        for _ in range(MAX_HIERARCHY):
            nxt = []
            for c in level:
                for child in sorted(self.children.get(c, ())):
                    if child in seen:
                        continue
                    seen.add(child)
                    nxt.append(child)
                    cand = '%s->%s%s' % (child, name, desc)
                    if cand in self.app and cand != exclude:
                        out.append(cand)
            level = nxt
        return out

    def nlocals(self, method):
        sig = method['signature']
        if sig not in self.locals:
            self.locals[sig] = _locals(method)
        return self.locals[sig]


def _regs(text, nlocals):
    """Register names in an invoke list -> register numbers."""
    def num(r):
        n = int(r[1:])
        return n + nlocals if r[0] == 'p' else n
    names = cg.expand_registers(text)
    if len(names) == 3 and names[1] == '..':
        return list(range(num(names[0]), num(names[2]) + 1))
    return [num(r) for r in names]


def _operands(rest, nlocals):
    out = []
    for tok in rest.split(','):
        tok = tok.strip()
        if len(tok) > 1 and tok[0] in 'vp' and tok[1:].isdigit():
            n = int(tok[1:])
            out.append(n + nlocals if tok[0] == 'p' else n)
    return out


def _literal(rest):
    """'v0, "text"' -> 'text' (escapes left as written)."""
    i = rest.find('"')
    return rest[i + 1:rest.rfind('"')] if i >= 0 else None


def _class_of(name):
    return 'L%s;' % name.replace('.', '/')


def _val_invoke(cls, name, desc, recv, args, vals):
    """Track Intent, ComponentName and IntentFilter targets through one call.

    Returns the value the next move-result receives, or None."""
    def get(r, kind):
        v = vals.get(r)
        return v[1] if v and v[0] == kind else None

    def target(r):
        text = get(r, 'str')
        return _class_of(text) if text else get(r, 'class')

    if cls == INTENT and recv is not None:
        it = get(recv, 'intent')
        if it is None:
            return None
        if name == '<init>' and args:
            other = get(args[0], 'intent')
            if other is not None:
                it.update(other)
            action = get(args[0], 'str')
            if action and len(args) <= 2:
                it['action'] = action
            if len(args) >= 2 and get(args[-1], 'class'):
                it['cls'] = get(args[-1], 'class')
        elif name == 'setAction' and args:
            it['action'] = get(args[0], 'str')
        elif name in ('setClass', 'setClassName') and args:
            it['cls'] = target(args[-1]) or it.get('cls')
        elif name == 'setPackage' and args:
            it['pkg'] = get(args[0], 'str') or '?'
        elif name == 'setComponent' and args:
            it['cls'] = get(args[0], 'comp') or it.get('cls')
        if desc.endswith(')' + INTENT):
            return vals[recv]
        return None
    if cls == COMPONENT_NAME and name == '<init>' and recv in vals and args:
        vals[recv] = ('comp', target(args[-1]))
    elif cls == INTENT_FILTER and name in ('<init>', 'addAction') and args:
        actions = get(recv, 'filter')
        action = get(args[0], 'str')
        if actions is not None and action:
            actions.add(action)
    return None


def _val_op(op, rest, ops, vals, pending_val):
    """Track constant strings, classes and new objects in plain instructions."""
    if not ops:
        return
    dst = ops[0]
    if op.startswith('move-result'):
        vals.pop(dst, None)
        if pending_val is not None:
            vals[dst] = pending_val
    elif op.startswith('const-string'):
        vals[dst] = ('str', _literal(rest))
    elif op == 'const-class':
        vals[dst] = ('class', rest.split(',')[-1].strip())
    elif op == 'new-instance':
        kind = rest.split(',')[-1].strip()
        if kind == INTENT:
            vals[dst] = ('intent', {'cls': None, 'action': None})
        elif kind == COMPONENT_NAME:
            vals[dst] = ('comp', None)
        elif kind == INTENT_FILTER:
            vals[dst] = ('filter', set())
        else:
            vals[dst] = ('obj', kind)
    elif op.startswith('move') and op != 'move-exception' and len(ops) == 2:
        vals.pop(dst, None)
        if ops[1] in vals:
            vals[dst] = vals[ops[1]]
    elif op.startswith(_CLEARS) or op.startswith('aget'):
        vals.pop(dst, None)


def _dynamic_receivers(ctx):
    """action -> classes of receivers registered in code for it."""
    out = {}
    for method in ctx.methods.values():
        if not any('registerReceiver' in line for _, line in method['body']):
            continue
        nl = ctx.nlocals(method)
        vals = {} if method['static'] else {nl: ('obj', method['class'])}
        pending_val = None
        for _, line in method['body']:
            if line[0] in '.:#':
                continue
            op, _, rest = line.partition(' ')
            if op.startswith('invoke-'):
                inv = cg.parse_invoke(line)
                pending_val = None
                if not inv:
                    continue
                opc, regtext, sig = inv
                cls, name, desc = cg.split_ref(sig)
                regs = _regs(regtext, nl)
                static = 'static' in opc
                recv = None if static or not regs else regs[0]
                args = regs if static else regs[1:]
                if name == 'registerReceiver' and len(args) >= 2:
                    rv, fv = vals.get(args[0]), vals.get(args[1])
                    if rv and rv[0] == 'obj' and fv and fv[0] == 'filter':
                        for action in fv[1]:
                            out.setdefault(action, set()).add(rv[1])
                    continue
                pending_val = _val_invoke(cls, name, desc, recv, args, vals)
                continue
            _val_op(op, rest, _operands(rest, nl), vals, pending_val)
            pending_val = None
    return out


def _icc_targets(ctx, intent, label):
    """Classes that an Intent with this target info reaches through label."""
    if intent.get('cls'):
        return [intent['cls']]
    action = intent.get('action')
    if not action:
        return []
    kinds = _ICC_TYPES[label]
    out = []
    for comp in ctx.components:
        if comp.get('type') in kinds and any(
                action in (f.get('actions') or ())
                for f in comp.get('intent_filters') or ()):
            out.append(_class_of(comp['name']))
    if label == 'sendBroadcast':
        out += sorted(ctx.dynamic.get(action, ()))
    return sorted(set(out))


def _implicit_activity(label, args, vals):
    """True when a startActivity sink gets an Intent known to name only an
    action: no explicit class, component or package (CWE-927, the Intent can
    resolve to another app's activity with a matching intent filter)."""
    if label != 'startActivity':
        return False
    for r in args:
        v = vals.get(r)
        if v and v[0] == 'intent':
            it = v[1]
            return bool(it.get('action')) and not it.get('cls') and not it.get('pkg')
    return False


def _record(ctx, method, origin, label, no, line, depth, cwe=None):
    src_label, _src_file, src_no, src_text, hops = origin[:5]
    key = (method['file'], no, src_no)
    conf = CONFIDENCE[min(depth + hops, 2)]
    old = ctx.findings.get(key)
    if old and CONFIDENCE.index(old['confidence']) <= CONFIDENCE.index(conf):
        return
    ctx.findings[key] = {
        'component': _dotted(method['class']),
        'component_type': 'class',
        'issue': 'taint-flow',
        'pattern': 'taint:%s->%s' % (src_label, label),
        'cwe': cwe or SINKS[label],
        'confidence': conf,
        'file': method['file'],
        'line': no,
        'evidence': ('%ssource L%d: %s | sink L%d: %s'
                     % (origin[5] + ' | ' if len(origin) > 5 else '',
                        src_no, src_text, no, line)),
        'source_line': src_no,
        'sink_line': no,
    }


def _icc_edges(ctx, method, label, args, taint, vals, no, depth):
    """Record the components that a tainted Intent passed to label reaches."""
    for r in args:
        v = vals.get(r)
        if r not in taint or not v or v[0] != 'intent':
            continue
        origin = taint[r]
        hops = origin[4] + depth + 1
        for target in _icc_targets(ctx, v[1], label):
            step = '%s.%s L%d (%s) -> %s' % (
                _dotted(method['class']), method['name'], no, label,
                _dotted(target))
            path = (origin[5] + ' -> ' + step if len(origin) > 5
                    else 'icc ' + step)
            key = (target, method['file'], no)
            old = ctx.edges.get(key)
            if old is None or hops < old[0]:
                ctx.edges[key] = (hops, path)


def _icc_pass(ctx):
    """Scan the receiving components of the recorded Intent edges and add
    the flows whose sink location is not reported yet."""
    main = dict(ctx.findings)
    done = set()
    extra = {}
    for _ in range(MAX_ICC):
        todo = [(k, v) for k, v in sorted(ctx.edges.items()) if k not in done]
        if not todo:
            break
        for key, (hops, path) in todo:
            done.add(key)
            entries = [m for _s, m in sorted(ctx.methods.items())
                       if m['class'] == key[0] and m['name'] in _ICC_ENTRIES]
            ctx.icc = (hops, path)
            ctx.visited = {}
            ctx.findings = {}
            for m in entries:
                _scan(ctx, m, {}, 0)
            ctx.icc = None
            for f in ctx.findings.values():
                if not f['pattern'].startswith('taint:icc:'):
                    continue
                loc = (f['file'], f['sink_line'])
                old = extra.get(loc)
                if old is None or (CONFIDENCE.index(f['confidence'])
                                   < CONFIDENCE.index(old['confidence'])):
                    extra[loc] = f
    reported = {(f['file'], f['sink_line']) for f in main.values()}
    ctx.findings = main
    for loc, f in extra.items():
        if loc not in reported:
            ctx.findings[loc + ('icc',)] = f


def _load_components(decoded_dir):
    path = os.path.join(decoded_dir, 'AndroidManifest.xml')
    if _apk is None or not os.path.isfile(path):
        return []
    try:
        return _apk.parse_manifest(path).get('components', [])
    except Exception:     # unreadable manifest: no inter-component flows
        return []


def _scan(ctx, method, seeds, depth):
    """Scan one method; return the origin of a tainted return value, or None."""
    key = (method['signature'], frozenset(seeds.items()))
    if key in ctx.visited:
        return ctx.visited[key]
    ctx.visited[key] = None   # guards recursion
    returned = None

    nl = ctx.nlocals(method)
    body = method['body']
    tries = _try_ranges(body)
    taint = dict(seeds)      # register -> origin (label, file, line_no, text, hops)
    cursors = set()
    pending = None           # what the next move-result receives
    vals = {}                # register -> ('str'|'class'|'intent'|..., value)
    pending_val = None

    def clear(reg):
        taint.pop(reg, None)
        cursors.discard(reg)

    for idx, (no, line) in enumerate(body):
        if line[0] in '.:#':
            continue
        op, _, rest = line.partition(' ')

        if op.startswith('move-result'):
            dest = _operands(rest, nl)
            _val_op(op, rest, dest, vals, pending_val)
            pending_val = None
            if dest:
                clear(dest[0])
                if pending == 'cursor':
                    cursors.add(dest[0])
                elif pending:
                    taint[dest[0]] = pending
            pending = None
            continue
        pending = None
        pending_val = None

        if op.startswith('invoke-'):
            inv = cg.parse_invoke(line)
            if not inv:
                continue
            opc, regtext, sig = inv
            cls, name, desc = cg.split_ref(sig)
            regs = _regs(regtext, nl)
            static = 'static' in opc
            recv = None if static or not regs else regs[0]
            args = regs if static else regs[1:]
            hit = [taint[r] for r in regs if r in taint]
            pending_val = _val_invoke(cls, name, desc, recv, args, vals)

            if name in _EQUALS and hit:
                for origin in hit:
                    for r in [r for r, o in taint.items() if o == origin]:
                        del taint[r]
                continue

            label = _sink(cls, name, desc)
            if label:
                arg_hit = [taint[r] for r in args if r in taint]
                in_try = any(a <= idx <= b for a, b in tries)
                if arg_hit and not in_try:
                    cwe = 'CWE-927' if _implicit_activity(label, args, vals) else None
                    _record(ctx, method, arg_hit[0], label, no, line, depth, cwe)
                if label in _ICC_TYPES:
                    _icc_edges(ctx, method, label, args, taint, vals, no, depth)

            if ctx.icc and cls == INTENT and name.startswith('get') and (
                    name.endswith('Extra') or name == 'getExtras'):
                hops, path = ctx.icc
                pending = ('icc:' + name, method['file'], no, line, hops, path)
                continue
            if ctx.icc and cls in _BUNDLES and name.startswith('get') and recv in taint:
                pending = taint[recv]
                continue
            src = _source(cls, name, recv, cursors)
            if src:
                pending = (src, method['file'], no, line, 0)
                continue
            if cls == 'Landroid/content/ContentResolver;' and name == 'query':
                pending = 'cursor'
                continue

            if hit:
                origin = hit[0]
                arg_origin = next((taint[r] for r in args if r in taint), None)
                ret = desc[desc.index(')') + 1:]
                if name == '<init>' and cls in _INIT_CLASSES and arg_origin:
                    taint[recv] = arg_origin
                elif cls == SB and name == 'append':
                    taint[recv] = origin
                    pending = origin
                elif (cls, name) in _PASS or name == 'toString':
                    pending = origin
                elif cls == INTENT and name in _INTENT_PUTS and arg_origin:
                    taint[recv] = arg_origin
                    pending = arg_origin
                elif cls in _BUNDLES and name.startswith('put') and arg_origin:
                    taint[recv] = arg_origin
                elif cls == INTENT and ret == INTENT and recv in taint:
                    pending = taint[recv]

            target = ctx.resolve(sig)
            if depth < MAX_DEPTH:
                # The resolved callee is also scanned without tainted
                # arguments, so that an app method returning a source value
                # (a getter) taints the caller. Subclass overrides are only
                # followed when an argument is tainted.
                targets = [target] if target else []
                if hit and opc.startswith(('invoke-virtual', 'invoke-interface')):
                    targets += ctx.overrides(sig, exclude=target)
                for t in targets:
                    callee = ctx.methods[t]
                    base = ctx.nlocals(callee)
                    callee_seeds = {base + i: taint[r]
                                    for i, r in enumerate(regs) if r in taint}
                    back = _scan(ctx, callee, callee_seeds, depth + 1)
                    if back and not pending:
                        # one more call level between the source and the caller
                        pending = back[:4] + (back[4] + 1,) + back[5:]
            continue

        ops = _operands(rest, nl)
        _val_op(op, rest, ops, vals, None)
        if not ops:
            continue
        if op in ('return', 'return-object', 'return-wide'):
            returned = returned or taint.get(ops[0])
        elif op.startswith('move'):
            if len(ops) == 2:
                dst, src = ops
                clear(dst)
                if src in taint:
                    taint[dst] = taint[src]
                if src in cursors:
                    cursors.add(dst)
        elif op in ('if-eqz', 'if-nez'):
            clear(ops[0])
        elif op.startswith('aget'):
            dst = ops[0]
            origin = taint.get(ops[1]) if len(ops) > 1 else None
            clear(dst)
            if origin:
                taint[dst] = origin
        elif op.startswith(_CLEARS):
            clear(ops[0])

    ctx.visited[key] = returned
    return returned


def analyze(decoded_dir, graph=None, skip_libs=True):
    """Return the list of taint-flow findings for the smali code in decoded_dir."""
    methods = {m['signature']: m for m in cg.parse_methods(decoded_dir, skip_libs)}
    if graph is None:
        graph, _ = cg.graph_from_methods(methods.values())
    elif isinstance(graph, tuple):
        graph = graph[0]
    app = {s for s in graph if s in methods}
    ctx = _Context(methods, app)
    ctx.components = _load_components(decoded_dir)
    ctx.dynamic = _dynamic_receivers(ctx)
    for sig in sorted(methods):
        _scan(ctx, methods[sig], {}, 0)
    if ctx.edges:
        _icc_pass(ctx)
    return sorted(ctx.findings.values(),
                  key=lambda f: (f['file'], f['sink_line'], f['source_line']))
