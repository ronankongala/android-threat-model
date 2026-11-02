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
"""

import call_graph as cg

# Sink label -> CWE.
#   rawQuery, execSQL      SQL built from input (CWE-89, SQL injection)
#   openFileOutput, File   file path built from input (CWE-22, path traversal)
#   sendBroadcast          input forwarded in an implicit broadcast that other
#                          apps can receive (CWE-927)
#   startActivity,         input forwarded to another component, which acts
#   startService           with this app's privileges (CWE-926)
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
_INTENT_PUTS = ('putExtra', 'putExtras', 'setData', 'setDataAndType')
_EQUALS = ('equals', 'equalsIgnoreCase')

_CLEARS = ('const', 'new-instance', 'new-array', 'filled-new-array', 'sget',
           'iget', 'instance-of', 'array-length', 'move-exception', 'cmp',
           'add-', 'sub-', 'mul-', 'div-', 'rem-', 'and-', 'or-', 'xor-',
           'shl-', 'shr-', 'ushr-', 'neg-', 'not-', 'int-to-', 'long-to-',
           'float-to-', 'double-to-')

MAX_DEPTH = 3
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
        self.locals = {}
        self.visited = {}     # (signature, seeds) -> origin of a tainted return, or None
        self.findings = {}

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


def _record(ctx, method, origin, label, no, line, depth):
    src_label, _src_file, src_no, src_text, hops = origin
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
        'cwe': SINKS[label],
        'confidence': conf,
        'file': method['file'],
        'line': no,
        'evidence': 'source L%d: %s | sink L%d: %s' % (src_no, src_text, no, line),
        'source_line': src_no,
        'sink_line': no,
    }


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

    def clear(reg):
        taint.pop(reg, None)
        cursors.discard(reg)

    for idx, (no, line) in enumerate(body):
        if line[0] in '.:#':
            continue
        op, _, rest = line.partition(' ')

        if op.startswith('move-result'):
            dest = _operands(rest, nl)
            if dest:
                clear(dest[0])
                if pending == 'cursor':
                    cursors.add(dest[0])
                elif pending:
                    taint[dest[0]] = pending
            pending = None
            continue
        pending = None

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
                    _record(ctx, method, arg_hit[0], label, no, line, depth)

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
                elif cls == INTENT and ret == INTENT and recv in taint:
                    pending = taint[recv]

            target = ctx.resolve(sig)
            if target and depth < MAX_DEPTH:
                # Also scanned without tainted arguments, so that an app
                # method returning a source value (a getter) taints the caller.
                callee = ctx.methods[target]
                base = ctx.nlocals(callee)
                callee_seeds = {base + i: taint[r]
                                for i, r in enumerate(regs) if r in taint}
                back = _scan(ctx, callee, callee_seeds, depth + 1)
                if back and not pending:
                    # one more call level between the source and the caller
                    pending = back[:4] + (back[4] + 1,)
            continue

        ops = _operands(rest, nl)
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
    for sig in sorted(methods):
        _scan(ctx, methods[sig], {}, 0)
    return sorted(ctx.findings.values(),
                  key=lambda f: (f['file'], f['sink_line'], f['source_line']))
