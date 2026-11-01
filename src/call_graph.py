"""Method call graph built from the smali files of an apktool output folder.

build(decoded_dir, skip_libs=True) returns (graph, reverse):
  graph    maps each method signature 'Lpkg/Cls;->name(args)ret' defined in the
           app to the ordered, de-duplicated list of signatures it calls
  reverse  maps each callee signature to the list of its callers

Every defined method is a key of graph, even if it calls nothing. Callees are
recorded as written in the invoke instruction, so a call to an inherited or
framework method appears under the class named at the call site.

Only invoke instructions are read: invoke-virtual, invoke-direct, invoke-static,
invoke-super, invoke-interface and their /range forms.

parse_methods(decoded_dir, skip_libs=True) yields one dict per defined method:
  class      'Lpkg/Cls;'
  super      superclass descriptor, or None
  signature  'Lpkg/Cls;->name(args)ret'
  name, desc method name and descriptor '(args)ret'
  static     True for static methods
  file       path relative to decoded_dir, forward slashes
  line       line number of the .method directive
  body       list of (line_no, stripped_line) between .method and .end method,
             blank lines left out

With skip_libs=True, classes under LIBRARY_PREFIXES are not parsed.
graph_from_methods(methods) builds the graph from parsed methods, and
parse_invoke(line) and expand_registers(text) are shared with taint_analyzer.
"""

import os
import re

LIBRARY_PREFIXES = ('android/support/', 'android/arch/', 'androidx/',
                    'kotlin/', 'kotlinx/', 'com/google/')

INVOKE_RE = re.compile(
    r'^(invoke-(?:virtual|direct|static|super|interface)(?:/range)?)\s+'
    r'\{([^}]*)\},\s*(\S+->\S+)$')
METHOD_RE = re.compile(r'^\.method\s+(.*?)(\S+)$')


def _is_library(rel):
    # rel looks like 'smali_classes2/android/support/v4/Foo.smali'
    parts = rel.split('/', 1)
    inner = parts[1] if len(parts) > 1 else rel
    return inner.startswith(LIBRARY_PREFIXES)


def _smali_files(decoded_dir, skip_libs):
    for entry in sorted(os.listdir(decoded_dir)):
        top = os.path.join(decoded_dir, entry)
        if not (entry.startswith('smali') and os.path.isdir(top)):
            continue
        for root, dirs, files in os.walk(top):
            dirs.sort()
            for name in sorted(files):
                if not name.endswith('.smali'):
                    continue
                path = os.path.join(root, name)
                rel = os.path.relpath(path, decoded_dir).replace(os.sep, '/')
                if skip_libs and _is_library(rel):
                    continue
                yield path, rel


def split_ref(ref):
    """'Lpkg/Cls;->name(args)ret' -> ('Lpkg/Cls;', 'name', '(args)ret')."""
    cls, rest = ref.split('->', 1)
    i = rest.index('(')
    return cls, rest[:i], rest[i:]


def parse_invoke(line):
    """Return (opcode, register_text, callee_signature) or None."""
    m = INVOKE_RE.match(line)
    if not m:
        return None
    return m.group(1), m.group(2).strip(), m.group(3)


def expand_registers(text):
    """'v0, p1' -> ['v0', 'p1']; 'v0 .. v3' -> ['v0', 'v1', 'v2', 'v3'].

    A range that mixes v and p names is returned as its two ends, since the
    caller needs the method's local count to expand it (see taint_analyzer).
    """
    if not text:
        return []
    if '..' in text:
        a, b = [s.strip() for s in text.split('..')]
        if a[0] == b[0]:
            return ['%s%d' % (a[0], n) for n in range(int(a[1:]), int(b[1:]) + 1)]
        return [a, '..', b]
    return [r.strip() for r in text.split(',') if r.strip()]


def parse_file(path, rel):
    """Yield the method dicts of one .smali file."""
    with open(path, encoding='utf-8', errors='replace') as f:
        lines = f.read().splitlines()
    cls = sup = None
    current = None
    for no, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line:
            continue
        if current is None:
            if line.startswith('.class'):
                cls = line.split()[-1]
            elif line.startswith('.super'):
                sup = line.split()[-1]
            elif line.startswith('.method'):
                m = METHOD_RE.match(line)
                if not m or cls is None:
                    continue
                flags, namedesc = m.group(1).split(), m.group(2)
                i = namedesc.index('(')
                current = {
                    'class': cls,
                    'super': sup,
                    'signature': '%s->%s' % (cls, namedesc),
                    'name': namedesc[:i],
                    'desc': namedesc[i:],
                    'static': 'static' in flags,
                    'file': rel,
                    'line': no,
                    'body': [],
                }
        elif line.startswith('.end method'):
            yield current
            current = None
        else:
            current['body'].append((no, line))


def parse_methods(decoded_dir, skip_libs=True):
    """Yield one dict per method defined in decoded_dir (see module docstring)."""
    for path, rel in _smali_files(decoded_dir, skip_libs):
        yield from parse_file(path, rel)


def callees(method):
    """Ordered, de-duplicated callee signatures of one parsed method."""
    seen = {}
    for _, line in method['body']:
        if line.startswith('invoke-'):
            inv = parse_invoke(line)
            if inv:
                seen.setdefault(inv[2], None)
    return list(seen)


def graph_from_methods(methods):
    graph = {}
    for m in methods:
        graph[m['signature']] = callees(m)
    reverse = {}
    for caller, called in graph.items():
        for callee in called:
            reverse.setdefault(callee, []).append(caller)
    return graph, reverse


def build(decoded_dir, skip_libs=True):
    """Return (graph, reverse) for the smali code in decoded_dir."""
    return graph_from_methods(parse_methods(decoded_dir, skip_libs))
