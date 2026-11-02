"""Code level findings from the smali that apktool writes.

analyze(decoded_dir) returns a list of findings, each a dict with:
  component       dotted class name (inner classes keep the $)
  component_type  'class', or 'application' (component '(application)') for
                  app wide findings such as certificate_pinning_missing
  file            smali path relative to decoded_dir, forward slashes
  line            1-based line number in that file
  pattern, issue  the pattern name (the two keys hold the same value)
  cwe             CWE ID for the pattern (see PATTERNS)
  confidence      high, medium or low
  evidence        the smali line that triggered the finding, stripped

Every smali* folder is read, but library classes (android/support/, androidx/,
kotlin/, com/google/ and any class in an android.* package) are skipped so only
the app's own code is analyzed.

Each method (.method ... .end method) is read top to bottom with a simple
register model: constant strings and ints, byte and char arrays made from
literals (const-string then getBytes/toCharArray, fill-array-data, Base64.decode
of a literal), string resources, static fields set once from a constant, Intent
and StringBuilder objects, and values read from incoming intents. Branches are
not followed, so the model is a heuristic. Methods whose parameters reach an
IV, key or PBE sink get a summary, and a call that passes a constant into such a
parameter reports the sink at medium confidence.

Patterns:
  ecb_mode                     Cipher.getInstance with ECB, or bare AES/DES/DESede
  constant_iv                  IvParameterSpec built from a constant byte array
  hardcoded_key                SecretKeySpec (or a seeded KeyGenerator) from a constant
  hardcoded_key_pbe            PBEKeySpec with a constant salt (low when only the
                               password is constant)
  empty_trustmanager           X509TrustManager whose check*Trusted is empty (high),
                               or a checkServerTrusted with code that cannot throw
                               (medium): no throw, and no call to a method named
                               *check* or *verify* outside a try range whose
                               CertificateException handler returns without
                               rethrowing (P-3, linear scan). An empty
                               checkClientTrusted is low when checkServerTrusted
                               of the same class can throw (clients never call it)
  hostname_not_verified        HostnameVerifier.verify that returns true: only
                               const/4 vN, 0x1 and return (high), or any branch-free
                               body that returns a const/4 0x1 register (medium);
                               or ALLOW_ALL_HOSTNAME_VERIFIER
  insecure_ssl_socket_factory  SSLCertificateSocketFactory.getInsecure, or
                               createSocket / getSocket taking an InetAddress (no
                               hostname check)
  js_enabled                   WebSettings.setJavaScriptEnabled(true)
  webview_file_access          setAllowFileAccess* / setAllowUniversalAccess* (true)
  sql_injection_raw            rawQuery/execSQL on a string built by concatenation
  sql_injection_no_args        query/update/delete with a selection but null args
  directory_traversal          file created from a name read from an intent
  clipboard_sensitive          text from an input field put on the clipboard
                               (setPrimaryClip in a method that calls getPassword
                               or reads an input field). Also (medium) password
                               text tracked in the register model:
                               ClipData.newPlainText / newHtmlText with text from
                               getPassword(), or from getText (then toString) on
                               the view of findViewById(const id) where the id is a
                               password field in res/layout*/*.xml (inputType
                               textPassword, numberPassword, textVisiblePassword,
                               textWebPassword, or password="true"; id names mapped
                               to ints through res/values/public.xml), and the
                               setPrimaryClip of that ClipData. Views and password
                               text kept in instance fields are followed. The
                               evidence names the password field
  dynamic_code_load            DexClassLoader / PathClassLoader created
  sticky_broadcast             sendStickyBroadcast / sendStickyOrderedBroadcast
  sticky_broadcast_receiver    (medium) onReceive of an app receiver registered for
                               the action of a sticky broadcast the app sends
                               (action from new Intent("...") or setAction("...")),
                               in a manifest intent filter or through
                               registerReceiver with an IntentFilter built from that
                               string, that acts without checking the data: no
                               isInitialStickyBroadcast, getAction compared with
                               equals, checkCallingPermission (or similar) call, and
                               no null check or comparison of an extra. Receivers
                               with a manifest permission or registered with a
                               broadcast permission are skipped. Any app can
                               replace a sticky broadcast, so its data is untrusted
  implicit_broadcast           sendBroadcast with an Intent that names no target
  pending_intent_empty         PendingIntent wrapping an empty Intent, or one built
                               with new Intent() and no action in the constructor
  pending_intent_implicit      PendingIntent.getActivity / getBroadcast / getService
                               wrapping an Intent built in the same method with no
                               setPackage, setClass, setClassName (or other target)
                               call before the PendingIntent call
  pending_intent_mutable       (high) PendingIntent.getActivity / getActivities /
                               getBroadcast / getService / getForegroundService
                               whose flags argument is a constant with neither
                               FLAG_IMMUTABLE (0x4000000) nor FLAG_MUTABLE
                               (0x2000000), which apps targeting API 31+ must set.
                               P-4: skipped when targetSdkVersion (apktool.yml or
                               the manifest) is below 31; reported when it is 31+
                               or unknown. Flags the register model cannot resolve
                               to a constant are not reported
  dynamic_receiver_no_permission  (high) Context.registerReceiver with no
                               broadcastPermission: the (receiver, filter) or
                               (receiver, filter, flags) overload, or a null
                               permission in the (receiver, filter, String,
                               Handler[, flags]) overloads. Skipped for
                               LocalBroadcastManager (app local) and when the flags
                               hold RECEIVER_NOT_EXPORTED (0x4); medium when the
                               flags are not a known constant
  no_validity_check            onReceive starts a component without checking the action
  ordered_broadcast_priority   BroadcastReceiver subclass whose onReceive calls
                               setResult, setResultData, setResultExtras or
                               abortBroadcast, declared in AndroidManifest.xml with an
                               intent filter of android:priority greater than 0
                               (medium); or, whatever the priority (including none),
                               any receiver subclass (direct, or through app classes)
                               whose onReceive invoke-virtual's one of those methods on
                               itself, an app superclass or BroadcastReceiver (medium).
                               One finding per receiver; the priority match wins.
  unique_ids                   device identifiers (IMEI, serial, ANDROID_ID)
  certificate_pinning_missing  application level (high). The network security
                               config (android:networkSecurityConfig, else
                               res/xml/network_security_config.xml) has no pin-set
                               with a pin under any domain-config; or there is no
                               config and usesCleartextTraffic is not "false".
                               Gated on the app's own smali opening network or TLS
                               connections (URL.openConnection, HttpURLConnection,
                               HttpsURLConnection, SSLSocketFactory, SSLContext,
                               okhttp3, new Socket), so apps with no network code
                               are not flagged; classes of bundled network
                               libraries (okhttp3, okio, retrofit2) do not count.
                               Also skipped when the code pins by itself: okhttp3
                               CertificatePinner, or a KeyStore filled with
                               setCertificateEntry and passed to
                               TrustManagerFactory.init.
  fragment_injection           class extending PreferenceActivity (directly or through
                               app classes) that declares no isValidFragment (high;
                               medium when targetSdkVersion is 19 or more, where the
                               framework default throws instead of loading any
                               fragment), or whose isValidFragment is branch-free and
                               returns const/4 0x1 (medium). Also (medium) a call to
                               Fragment.instantiate, or to an app method returning a
                               Fragment that calls Class.forName or
                               Fragment.instantiate, from a class whose outer class
                               (with its inner classes) reads an intent extra and
                               neither declares nor calls a method whose name contains
                               "valid" (no check on the fragment name)
  webview_js_interface         method of an object passed to addJavascriptInterface
                               that does a sensitive operation (high): file access,
                               network, database (SQLiteDatabase, ContentResolver
                               query/insert/update/delete) or sending intents
                               (startActivity, startService, sendBroadcast and
                               similar), directly or in an app method it calls (one
                               level). The object's class comes from new-instance
                               (or this, or a parameter's declared type); when it
                               cannot be resolved, every app class with a
                               @JavascriptInterface method is checked. Only
                               @JavascriptInterface methods count, unless
                               minSdkVersion is below 17, where every public
                               method is exposed to JavaScript
  webview_file_url_access      (high) setAllowFileAccessFromFileURLs or
                               setAllowUniversalAccessFromFileURLs(true) after
                               setJavaScriptEnabled(true) in the same method (CWE-830);
                               without JavaScript enabled first it stays
                               webview_file_access
Rules from the miss analysis (A4-2, docs/notes/miss-analysis.md):
  null_deref_intent_extra      (medium) Intent.getStringExtra result used as a call
                               receiver with no if-eqz/if-nez on it and outside a try
                               range catching NullPointerException or a supertype,
                               in an exported component or its inner classes
  keystore_entry_unprotected   (medium) KeyStore.setEntry with a constant null
                               ProtectionParameter
  server_socket_no_peer_check  (medium) new ServerSocket(port[, backlog]), accept and
                               Socket get*Stream in one method with no
                               getInetAddress / getRemoteSocketAddress / getPort
  external_storage_io          (medium) File stream opened on a path under external
                               storage (getExternalFilesDir, Environment
                               getExternalStorageDirectory and similar)
  webview_ssl_proceed          onReceivedSslError calling SslErrorHandler.proceed
                               (high with no branch before it, else medium)
  webview_override_allows_all  (low) branch-free shouldOverrideUrlLoading returning false
"""
import os
import re
import xml.etree.ElementTree as ET

import apk
import call_graph

PATTERNS = {
    'ecb_mode': 'CWE-327',
    'constant_iv': 'CWE-329',
    'hardcoded_key': 'CWE-321',
    'hardcoded_key_pbe': 'CWE-760',
    'empty_trustmanager': 'CWE-295',
    'hostname_not_verified': 'CWE-297',
    'insecure_ssl_socket_factory': 'CWE-295',
    'js_enabled': 'CWE-749',
    'webview_file_access': 'CWE-829',
    'sql_injection_raw': 'CWE-89',
    'sql_injection_no_args': 'CWE-89',
    'directory_traversal': 'CWE-22',
    'clipboard_sensitive': 'CWE-200',
    'dynamic_code_load': 'CWE-494',
    'sticky_broadcast': 'CWE-927',
    'sticky_broadcast_receiver': 'CWE-927',
    'implicit_broadcast': 'CWE-927',
    'pending_intent_empty': 'CWE-927',
    'pending_intent_implicit': 'CWE-927',
    'pending_intent_mutable': 'CWE-927',
    'dynamic_receiver_no_permission': 'CWE-926',
    'no_validity_check': 'CWE-925',
    'ordered_broadcast_priority': 'CWE-927',
    'unique_ids': 'CWE-359',
    'certificate_pinning_missing': 'CWE-295',
    'fragment_injection': 'CWE-470',
    'webview_js_interface': 'CWE-749',
    'webview_file_url_access': 'CWE-830',
    'null_deref_intent_extra': 'CWE-476',
    'keystore_entry_unprotected': 'CWE-922',
    'server_socket_no_peer_check': 'CWE-940',
    'external_storage_io': 'CWE-922',
    'webview_ssl_proceed': 'CWE-295',
    'webview_override_allows_all': 'CWE-829',
}

CONFIDENCE = ('high', 'medium', 'low')

LIBRARY_PREFIXES = ('android/', 'androidx/', 'kotlin/', 'com/google/')
PASSES = 3   # rounds for static fields and method summaries to settle
INPUT_CALL_DEPTH = 2   # call levels followed to an input field read (clipboard_sensitive)

INVOKE_RE = re.compile(r'^(invoke-\S+)\s+\{([^}]*)\},\s*(\S+)$')
METHOD_REF_RE = re.compile(r'^(\S+?;)->([^(]+)\(([^)]*)\)(\S+)$')
FIELD_REF_RE = re.compile(r'(\S+?;->[^:\s]+:\S+)')
TYPE_RE = re.compile(r'\[*(?:L[^;]+;|[ZBSCIJFDV])')
CONST_STRING_RE = re.compile(r'^const-string(?:/jumbo)?\s+(\w+),\s*"(.*)"$')
FIELD_INIT_RE = re.compile(r'^\.field\s.*?([\w$]+):(\S+)\s*=\s*"(.*)"$')
METHOD_DECL_RE = re.compile(r'^\.method\s+(.*?)([^\s(]+)\(([^)]*)\)(\S+)$')

# Opcodes whose first register is read, not written.
NO_DEST = ('if-', 'aput', 'iput', 'sput', 'return', 'throw', 'monitor-', 'goto',
           'packed-switch', 'sparse-switch', 'fill-array-data', 'nop', 'check-cast')

INTENT_EXPLICIT = ('setClass', 'setClassName', 'setComponent', 'setPackage', 'setSelector')
CONTEXT_START = ('startService', 'startForegroundService', 'startActivity',
                 'startActivities', 'startActivityForResult', 'bindService')
TAINT_SOURCES = ('getStringExtra', 'getExtras', 'getExtra', 'getBundleExtra',
                 'getCharSequenceExtra')
PENDING_INTENT_FACTORIES = ('getActivity', 'getActivities', 'getBroadcast', 'getService',
                            'getForegroundService')
FLAG_IMMUTABLE = 0x4000000   # PendingIntent.FLAG_IMMUTABLE
FLAG_MUTABLE = 0x2000000     # PendingIntent.FLAG_MUTABLE (API 31)
# FLAG_IMMUTABLE or FLAG_MUTABLE is required for apps targeting this API level or higher.
MUTABILITY_REQUIRED_SDK = 31
RECEIVER_NOT_EXPORTED = 0x4  # Context.RECEIVER_NOT_EXPORTED (API 33)
SINK_KINDS = {'iv': 'constant_iv', 'key': 'hardcoded_key', 'pbe_salt': 'hardcoded_key_pbe',
              'pbe_pass': 'hardcoded_key_pbe'}


# ---------------------------------------------------------------- parsing

def _is_library(rel):
    return rel.startswith(LIBRARY_PREFIXES)


def _class_files(decoded_dir):
    for entry in sorted(os.listdir(decoded_dir)):
        root = os.path.join(decoded_dir, entry)
        if not entry.startswith('smali') or not os.path.isdir(root):
            continue
        for dirpath, _, files in os.walk(root):
            for name in sorted(files):
                if not name.endswith('.smali'):
                    continue
                path = os.path.join(dirpath, name)
                if _is_library(os.path.relpath(path, root).replace(os.sep, '/')):
                    continue
                yield path


def _dotted(descriptor):
    return descriptor[1:-1].replace('/', '.') if descriptor.startswith('L') else descriptor


def _types(desc):
    return TYPE_RE.findall(desc)


def _parse_class(path, decoded_dir):
    with open(path, encoding='utf-8', errors='replace') as f:
        lines = f.read().splitlines()
    cls = {'file': os.path.relpath(path, decoded_dir).replace(os.sep, '/'),
           'name': None, 'super': None, 'super_line': None, 'implements': [],
           'field_inits': {}, 'methods': []}
    method = None
    for no, raw in enumerate(lines, 1):
        text = raw.strip()
        if method is not None:
            if text == '.end method':
                cls['methods'].append(method)
                method = None
            elif text and not text.startswith('#'):
                method['body'].append((no, text))
            continue
        if text.startswith('.class '):
            cls['name'] = text.split()[-1]
        elif text.startswith('.super '):
            cls['super'] = text.split()[-1]
            cls['super_line'] = no
        elif text.startswith('.implements '):
            cls['implements'].append(text.split()[-1])
        elif text.startswith('.field '):
            m = FIELD_INIT_RE.match(text)
            if m and m.group(2) == 'Ljava/lang/String;' and ' static ' in text + ' ':
                cls['field_inits']['%s->%s:%s' % (cls['name'], m.group(1), m.group(2))] = m.group(3)
        elif text.startswith('.method '):
            m = METHOD_DECL_RE.match(text)
            if m:
                method = {'name': m.group(2), 'desc': m.group(3), 'ret': m.group(4),
                          'static': ' static ' in ' ' + m.group(1), 'line': no,
                          'decl': text, 'body': []}
    if cls['name'] and _is_library(cls['name'][1:]):
        return None
    return cls if cls['name'] else None


def _regs(spec):
    spec = spec.strip()
    if not spec:
        return []
    if '..' in spec:
        a, b = [s.strip() for s in spec.split('..')]
        return ['%s%d' % (a[0], i) for i in range(int(a[1:]), int(b[1:]) + 1)]
    return [r.strip() for r in spec.split(',')]


def _int(token):
    try:
        return int(token, 0)
    except ValueError:
        return None


BLOCK_STARTS = ('.annotation', '.array-data', '.packed-switch', '.sparse-switch')


def _code(body):
    """Instructions only: no directives, labels, annotation blocks (such as the
    Throws annotation of a method that declares exceptions) or array/switch
    payload data."""
    out, end = [], None
    for no, text in body:
        if end:
            if text == end:
                end = None
            continue
        if text.startswith(BLOCK_STARTS):
            end = '.end ' + text.split()[0][1:]
            continue
        if text.startswith(('.', ':')):
            continue
        out.append((no, text))
    return out


# ---------------------------------------------------------------- values

def _const_strength(v):
    """'high' or 'medium' when v is a constant string or array, else None."""
    if v and v[0] == 'str':
        return v[2]
    if v and v[0] == 'lit':
        return v[1]
    if v and v[0] == 'zero':   # new byte[n] never filled: all zeros
        return 'medium'
    return None


def _is_null(v):
    return v == ('int', 0)


def _tainted(v, objs):
    if not v:
        return False
    if v[0] == 'taint':
        return True
    if v[0] == 'concat':
        return v[1]
    if v[0] == 'obj':
        return 'tainted' in objs[v[1]]['flags']
    return False


class _Method:
    """Runs the register model over one method and reports what it sees."""

    def __init__(self, ctx, cls, method):
        self.ctx, self.cls, self.m = ctx, cls, method
        self.regs, self.objs, self.last = {}, [], None
        self.sig = '%s->%s(%s)%s' % (cls['name'], method['name'], method['desc'], method['ret'])
        k = 0
        if not method['static']:
            self.regs['p0'] = ('this',)
            k = 1
        self.param_types = {}   # register number -> declared type
        for t in _types(method['desc']):
            self.regs['p%d' % k] = ('param', k)
            self.param_types[k] = t
            k += 2 if t in ('J', 'D') else 1
        self.seen = set()       # names of methods invoked so far
        self.action_read = False
        self.action_checked = False
        self.arrays = {}        # label -> line of fill-array-data payload

    def report(self, pattern, conf, no, text):
        self.ctx.emit(self.cls, pattern, conf, no, text)

    def new_obj(self, kind):
        self.objs.append({'kind': kind, 'flags': set()})
        return ('obj', len(self.objs) - 1)

    def obj(self, v, kind=None):
        if v and v[0] == 'obj' and (kind is None or self.objs[v[1]]['kind'] == kind):
            return self.objs[v[1]]
        return None

    def run(self):
        for no, text in _code(self.m['body']):
            parts = text.split(None, 1)
            op = parts[0]
            rest = parts[1] if len(parts) > 1 else ''
            if op.startswith('invoke-'):
                m = INVOKE_RE.match(text)
                if m:
                    self.last = None
                    self.invoke(no, text, _regs(m.group(2)), m.group(3))
                continue
            self.simple(no, text, op, rest)

    def simple(self, no, text, op, rest):
        ops = [o.strip() for o in rest.split(',')]
        dest = ops[0] if ops else None
        if op.startswith('move-result'):
            self.regs[dest] = self.last
            self.last = None
        elif op.startswith('const-string'):
            m = CONST_STRING_RE.match(text)
            if m:
                self.regs[m.group(1)] = ('str', m.group(2), 'high')
        elif op.startswith('const') and not op.startswith('const-class'):
            n = _int(ops[1]) if len(ops) > 1 else None
            self.regs[dest] = ('int', n) if n is not None else None
        elif op.startswith('move') and not op.startswith('move-exception'):
            self.regs[dest] = self.regs.get(ops[1]) if len(ops) > 1 else None
        elif op == 'new-array':
            self.regs[dest] = ('zero', object())   # unique, so it can be found by identity
        elif op == 'fill-array-data':
            self.regs[dest] = ('lit', 'high')
        elif op == 'new-instance':
            t = ops[1] if len(ops) > 1 else ''
            if t == 'Landroid/content/Intent;':
                self.regs[dest] = self.new_obj('intent')
            elif t in ('Ljava/lang/StringBuilder;', 'Ljava/lang/StringBuffer;'):
                self.regs[dest] = self.new_obj('sb')
            elif t == 'Landroid/content/IntentFilter;':
                self.regs[dest] = self.new_obj('filter')
            else:
                self.regs[dest] = ('new', t)
        elif op.startswith('sget'):
            m = FIELD_REF_RE.search(rest)
            ref = m.group(1) if m else ''
            self.regs[dest] = self.ctx.fields.get(ref)
            if ref.endswith('->ALLOW_ALL_HOSTNAME_VERIFIER:Lorg/apache/http/conn/ssl/X509HostnameVerifier;'):
                self.report('hostname_not_verified', 'medium', no, text)
        elif op.startswith('sput'):
            m = FIELD_REF_RE.search(rest)
            if m:
                self.ctx.field_write(m.group(1), self.regs.get(dest), self.m['name'] == '<clinit>')
        elif op.startswith('iput-object'):
            # Views found by a password field id, and text read from one, kept
            # in instance fields (clipboard_sensitive across methods).
            m = FIELD_REF_RE.search(rest)
            v = self.regs.get(dest)
            if m and v and v[0] in ('view', 'pw'):
                self.ctx.ui_fields[m.group(1)] = v
        elif op.startswith('iget-object'):
            m = FIELD_REF_RE.search(rest)
            self.regs[dest] = self.ctx.ui_fields.get(m.group(1)) if m else None
        elif op.startswith(NO_DEST):
            pass
        elif dest:
            self.regs[dest] = None

    # -- invokes

    def invoke(self, no, text, regs, ref):
        m = METHOD_REF_RE.match(ref)
        if not m:
            return
        owner, name, desc, ret = m.groups()
        vals = [self.regs.get(r) for r in regs]
        static = text.startswith('invoke-static')
        types = _types(desc)
        args, pos = [], 0 if static else 1     # one value per declared parameter
        for t in types:
            args.append(vals[pos] if pos < len(vals) else None)
            pos += 2 if t in ('J', 'D') else 1
        recv = None if static or not vals else vals[0]
        self.crypto(no, text, owner, name, desc, args)
        self.tls(no, text, owner, name, desc)
        self.webview(no, text, owner, name, args)
        self.js_interface(no, text, name, desc, args)
        self.sql(no, text, owner, name, types, args)
        self.files(no, text, owner, name, types, args)
        self.icc(no, text, owner, name, desc, args, recv)
        self.receivers(no, text, owner, name, desc, args, recv)
        self.misc(no, text, owner, name, args)
        self.summaries(owner + '->' + name + '(' + desc + ')' + ret, vals)
        self.flow(owner, name, desc, ret, args, recv, vals)
        self.seen.add(name)

    def flow(self, owner, name, desc, ret, args, recv, vals):
        """Track values through the calls the patterns care about."""
        if name == '<init>':
            o = self.obj(recv, 'intent')
            if o is not None:
                if desc == '':
                    o['flags'].add('noarg')   # new Intent(): no action given
                elif 'Ljava/lang/Class;' in desc or 'Landroid/content/ComponentName;' in desc:
                    o['flags'].add('explicit')
                elif desc.startswith('Landroid/content/Intent;'):
                    o['flags'].add('unknown')
                elif desc.startswith('Ljava/lang/String;'):
                    o['flags'].add('action')
                    if args and args[0] and args[0][0] == 'str':
                        o['action'] = args[0][1]
            o = self.obj(recv, 'sb')
            if o is not None and args:
                o['flags'].add('appended')
                if _tainted(args[0], self.objs):
                    o['flags'].add('tainted')
            if owner == 'Ljava/lang/String;' and args and recv and recv[0] == 'new':
                if _const_strength(args[0]):
                    self.set_reg_value(recv, ('str', None, _const_strength(args[0])))
            return
        if self.password_flow(owner, name, desc, ret, args, recv, vals):
            return
        if ret == 'V':
            # Arrays handed to other code (SecureRandom.nextBytes and so on) may be filled.
            for v in vals:
                if v and v[0] == 'zero':
                    self.mark_filled(v)
            return
        if owner == 'Ljava/lang/String;' and name in ('getBytes', 'toCharArray'):
            if recv and recv[0] == 'str':
                self.last = ('lit', recv[2])
            elif recv and recv[0] in ('param', 'taint', 'concat'):
                self.last = recv
        elif owner == 'Landroid/util/Base64;' and name == 'decode' and args:
            if args[0] and args[0][0] == 'str':
                self.last = ('lit', args[0][2])
        elif owner == 'Landroid/content/res/Resources;' and name == 'getString' and desc == 'I':
            self.last = ('str', None, 'medium')
        elif name in TAINT_SOURCES or (name == 'getString' and owner == 'Landroid/os/Bundle;'
                                      and _tainted(recv, self.objs)):
            self.last = ('taint',)
        elif self.obj(recv, 'intent') is not None and ret == 'Landroid/content/Intent;':
            o = self.obj(recv, 'intent')
            if name in INTENT_EXPLICIT:
                o['flags'].add('explicit')
            elif name == 'setAction':
                o['flags'].add('action')
                if args and args[0] and args[0][0] == 'str':
                    o['action'] = args[0][1]
            elif name in ('setData', 'setDataAndType'):
                o['flags'].add('action')
            self.last = recv
        elif self.obj(recv, 'sb') is not None and name in ('append', 'insert'):
            o = self.obj(recv, 'sb')
            o['flags'].add('appended')
            if any(_tainted(a, self.objs) for a in args):
                o['flags'].add('tainted')
            self.last = recv
        elif self.obj(recv, 'sb') is not None and name == 'toString':
            o = self.obj(recv, 'sb')
            self.last = ('concat', 'tainted' in o['flags'])
        elif owner == 'Ljava/lang/String;' and name in ('concat', 'format'):
            self.last = ('concat', any(_tainted(v, self.objs) for v in vals))
        elif owner == 'Ljava/lang/String;' and name in ('trim', 'toString', 'valueOf') and vals:
            self.last = vals[0] if vals[0] and vals[0][0] in ('str', 'taint', 'concat') else None

    def password_flow(self, owner, name, desc, ret, args, recv, vals):
        """Password text for clipboard_sensitive. findViewById(const id) gives
        ('view', id); getText on a view whose id is a password field in the
        layouts (ctx.password_ids), or any getPassword() call, gives
        ('pw', field description), which toString / trim / valueOf /
        subSequence keep; ClipData.newPlainText with such a text gives
        ('clip', field description). True when the call was handled."""
        if name in ('findViewById', 'requireViewById') and desc == 'I':
            a = args[0] if args else None
            self.last = ('view', a[1]) if a and a[0] == 'int' and a[1] is not None else None
            return True
        if name == 'getPassword' and not desc:
            self.last = ('pw', 'text from %s->getPassword()' % owner)
            return True
        if name == 'getText' and not desc and recv and recv[0] == 'view':
            field = self.ctx.password_ids.get(recv[1])
            self.last = ('pw', 'password field %s' % field) if field else None
            return field is not None
        src = recv if recv and recv[0] == 'pw' else (vals[0] if vals and vals[0] and vals[0][0] == 'pw'
                                                    else None)
        if src and name in ('toString', 'trim', 'valueOf', 'subSequence', 'getText'):
            self.last = src
            return True
        if owner == 'Landroid/content/ClipData;' and name in ('newPlainText', 'newHtmlText') \
                and len(args) > 1 and args[1] and args[1][0] == 'pw':
            self.last = ('clip', args[1][1])
            return True
        return False

    def set_reg_value(self, old, new):
        for r, v in list(self.regs.items()):
            if v is old:
                self.regs[r] = new

    def mark_filled(self, value):
        for r, v in list(self.regs.items()):
            if v is value:
                self.regs[r] = None

    # -- pattern checks

    def sink(self, kind, conf_value, no, text, pbe_low=False):
        """A constant reaching a sink is a finding; a parameter reaching it goes
        into this method's summary."""
        pattern = SINK_KINDS[kind]
        strength = _const_strength(conf_value)
        if strength:
            self.report(pattern, 'low' if pbe_low else strength, no, text)
        elif conf_value and conf_value[0] == 'param':
            self.ctx.add_summary(self.sig, conf_value[1], kind, self.cls, no, text)

    def crypto(self, no, text, owner, name, desc, args):
        if owner == 'Ljavax/crypto/Cipher;' and name == 'getInstance' and args:
            v = args[0]
            if v and v[0] == 'str' and v[1] is not None:
                algo = v[1].upper()
                if 'ECB' in algo or algo in ('AES', 'DES', 'DESEDE'):
                    self.report('ecb_mode', 'high', no, text)
        elif owner == 'Ljavax/crypto/spec/IvParameterSpec;' and name == '<init>' and args:
            self.sink('iv', args[0], no, text)
        elif owner == 'Ljavax/crypto/spec/SecretKeySpec;' and name == '<init>' and args:
            self.sink('key', args[0], no, text)
        elif owner == 'Ljavax/crypto/spec/PBEKeySpec;' and name == '<init>' and args:
            salt = args[1] if len(args) > 1 else None
            if _const_strength(salt) or (salt and salt[0] == 'param'):
                self.sink('pbe_salt', salt, no, text)
            elif _const_strength(args[0]):
                self.sink('pbe_pass', args[0], no, text, pbe_low=True)
        elif owner == 'Ljava/security/SecureRandom;' and name in ('<init>', 'setSeed') \
                and desc == '[B' and _const_strength(args[0]):
            self.ctx.seeded.add(self.sig)
        elif owner == 'Ljavax/crypto/KeyGenerator;' and name == 'init' and self.sig in self.ctx.seeded:
            self.report('hardcoded_key', 'medium', no, text)

    def tls(self, no, text, owner, name, desc):
        if owner != 'Landroid/net/SSLCertificateSocketFactory;':
            return
        if name == 'getInsecure':
            self.report('insecure_ssl_socket_factory', 'high', no, text)
        elif name in ('createSocket', 'getSocket') and 'Ljava/net/InetAddress;' in desc:
            self.report('insecure_ssl_socket_factory', 'medium', no, text)

    def webview(self, no, text, owner, name, args):
        if not owner.endswith('WebSettings;') or not args or args[0] != ('int', 1):
            return
        if name == 'setJavaScriptEnabled':
            self.report('js_enabled', 'medium', no, text)
            self.js_on = True
        elif name == 'setAllowFileAccess':
            self.report('webview_file_access', 'medium', no, text)
        elif name in ('setAllowFileAccessFromFileURLs', 'setAllowUniversalAccessFromFileURLs'):
            # A file:// page with JavaScript (enabled earlier in this method)
            # can read other files or any origin: CWE-830.
            if getattr(self, 'js_on', False):
                self.report('webview_file_url_access', 'high', no, text)
            else:
                self.report('webview_file_access', 'high', no, text)

    def js_interface(self, no, text, name, desc, args):
        """Record addJavascriptInterface calls with the class of the object
        passed, or None when the register model does not know it."""
        if name != 'addJavascriptInterface' or not args:
            return
        if not desc.startswith('Ljava/lang/Object;'):
            return
        v, t = args[0], None
        if v and v[0] == 'new':
            t = v[1]
        elif v and v[0] == 'this':
            t = self.cls['name']
        elif v and v[0] == 'param':
            t = self.param_types.get(v[1])
        self.ctx.js_interfaces.add((self.cls['file'], no, text, t))

    def sql(self, no, text, owner, name, types, args):
        db = owner == 'Landroid/database/sqlite/SQLiteDatabase;'
        if db and name in ('rawQuery', 'execSQL', 'rawQueryWithFactory'):
            q = args[1] if name == 'rawQueryWithFactory' and len(args) > 1 else (args[0] if args else None)
            if q and q[0] == 'concat':
                self.report('sql_injection_raw', 'high', no, text)
            elif 'append' in self.seen or 'concat' in self.seen:
                self.report('sql_injection_raw', 'medium', no, text)
            return
        resolver = owner in ('Landroid/content/ContentResolver;', 'Landroid/content/ContentProviderClient;')
        if not (db or resolver) or name not in ('query', 'update', 'delete', 'queryWithFactory'):
            return
        idx = [i for i in range(1, len(types))
               if types[i] == '[Ljava/lang/String;' and types[i - 1] == 'Ljava/lang/String;']
        if not idx or idx[-1] >= len(args):
            return
        i = idx[-1]
        selection, sel_args = args[i - 1], args[i]
        if _is_null(sel_args) and not _is_null(selection) and \
                not (selection and selection[0] == 'str' and '?' in (selection[1] or '')):
            self.report('sql_injection_no_args', 'medium', no, text)

    def files(self, no, text, owner, name, types, args):
        is_sink = (name == 'openFileOutput' or
                   (owner == 'Ljava/io/File;' and name == '<init>') or
                   (owner == 'Ljava/io/FileOutputStream;' and name == '<init>'
                    and 'Ljava/lang/String;' in types))
        if not is_sink:
            return
        names = [a for a, t in zip(args, types) if t == 'Ljava/lang/String;']
        if not names:
            return
        if any(_tainted(a, self.objs) for a in names):
            self.report('directory_traversal', 'high', no, text)
        elif any(s in self.seen for s in TAINT_SOURCES) and \
                not all(a and a[0] == 'str' for a in names):
            self.report('directory_traversal', 'medium', no, text)

    def icc(self, no, text, owner, name, desc, args, recv):
        if name in ('sendStickyBroadcast', 'sendStickyOrderedBroadcast',
                    'sendStickyBroadcastAsUser', 'sendStickyOrderedBroadcastAsUser'):
            self.report('sticky_broadcast', 'high', no, text)
            o = self.obj(args[0] if args else None, 'intent')
            if o is not None and o.get('action'):
                self.ctx.sticky_actions.add(o['action'])
                self.ctx.sticky_sends.add((o['action'], self.cls['name'], self.cls['file'], no, text))
        elif name in ('sendBroadcast', 'sendOrderedBroadcast', 'sendBroadcastAsUser') \
                and 'LocalBroadcastManager' not in owner and args:
            types = _types(desc)
            perm = [a for a, t in zip(args, types) if t == 'Ljava/lang/String;']
            if perm and perm[0] is not None and not _is_null(perm[0]):
                return   # receiver permission given
            o = self.obj(args[0], 'intent')
            if o is not None:
                if not o['flags'] & {'explicit', 'unknown'}:
                    self.report('implicit_broadcast', 'medium', no, text)
            elif not (self.seen & set(INTENT_EXPLICIT)) and not self.ctx_class_intent:
                self.report('implicit_broadcast', 'medium', no, text)
        elif owner == 'Landroid/app/PendingIntent;' and name in PENDING_INTENT_FACTORIES:
            self.pending_intent_flags(no, text, args)
            # getActivities takes an Intent[]: the Intent rules below do not apply.
            intent = args[2] if len(args) > 2 and name != 'getActivities' else None
            o = self.obj(intent, 'intent')
            if o is not None:
                flags = o['flags']
                if flags & {'explicit', 'unknown'}:
                    return
                # No setPackage, setClass, setClassName (or other target) call
                # on the Intent earlier in this method.
                self.report('pending_intent_implicit', 'medium', no, text)
                if 'noarg' in flags or 'action' not in flags:
                    self.report('pending_intent_empty', 'high', no, text)
        elif name in CONTEXT_START and self.is_on_receive and not self.action_checked:
            self.report('no_validity_check', 'medium', no, text)
        if owner == 'Landroid/content/Intent;' and name == 'getAction':
            self.action_read = True
        elif self.action_read and owner == 'Ljava/lang/String;' and name in (
                'equals', 'equalsIgnoreCase', 'contentEquals', 'hashCode', 'startsWith'):
            self.action_checked = True

    def pending_intent_flags(self, no, text, args):
        """pending_intent_mutable: the flags argument (4th parameter of every
        PendingIntent factory) is a known constant with neither FLAG_IMMUTABLE
        nor FLAG_MUTABLE. A flags value the register model does not know (a
        parameter, a field, a computed value) is not reported."""
        flags = args[3] if len(args) > 3 else None
        if not flags or flags[0] != 'int' or flags[1] is None:
            return
        if flags[1] & (FLAG_IMMUTABLE | FLAG_MUTABLE):
            return
        target = self.ctx.target_sdk
        if target is not None and target < MUTABILITY_REQUIRED_SDK:
            return   # P-4: the flag is only required from API 31
        evidence = ('%s [flags 0x%x: neither FLAG_IMMUTABLE nor FLAG_MUTABLE; required '
                    'for apps targeting API 31+ (targetSdkVersion %s), a mutable '
                    'PendingIntent lets the receiving app fill in its Intent]'
                    % (text, flags[1] & 0xffffffff, target if target is not None else 'unknown'))
        self.report('pending_intent_mutable', 'high', no, evidence)

    def receivers(self, no, text, owner, name, desc, args, recv):
        """IntentFilter actions and registerReceiver calls (for
        sticky_broadcast_receiver and dynamic_receiver_no_permission)."""
        f = self.obj(recv, 'filter')
        if f is not None and name in ('<init>', 'addAction') and args \
                and desc.startswith('Ljava/lang/String;') and args[0] and args[0][0] == 'str':
            f.setdefault('actions', set()).add(args[0][1])
            return
        if name != 'registerReceiver' or len(args) < 2 \
                or not desc.startswith('Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;'):
            return
        v, t = args[0], None
        if v and v[0] == 'new':
            t = v[1]
        elif v and v[0] == 'this':
            t = self.cls['name']
        elif v and v[0] == 'param':
            t = self.param_types.get(v[1])
        f = self.obj(args[1], 'filter')
        if f is not None and f.get('actions'):
            self.ctx.registered_actions.update(f['actions'])
        types = _types(desc)
        perm = len(types) > 2 and types[2] == 'Ljava/lang/String;' and len(args) > 2 \
            and args[2] is not None and not _is_null(args[2])
        if t and f is not None and f.get('actions'):
            self.ctx.dyn_receivers.add((t, tuple(sorted(f['actions'])), perm))
        if 'LocalBroadcastManager' not in owner:
            self.dynamic_receiver(no, text, types, args)

    def dynamic_receiver(self, no, text, types, args):
        """dynamic_receiver_no_permission: Context.registerReceiver with no
        broadcastPermission. Overloads (after receiver and filter):
          ()                        no permission
          (int flags)               no permission
          (String, Handler)         permission is args[2]
          (String, Handler, int)    permission is args[2]
        Only a permission known to be null counts as missing (a string from a
        parameter or field is assumed to be a permission). Skipped when the
        flags hold RECEIVER_NOT_EXPORTED (0x4); flags the register model cannot
        resolve lower the confidence to medium."""
        rest = types[2:]
        if rest and rest[0] == 'Ljava/lang/String;':
            if not _is_null(args[2] if len(args) > 2 else None):
                return
            how = 'null broadcastPermission'
        else:
            how = 'no broadcastPermission argument'
        conf = 'high'
        if rest and rest[-1] == 'I':
            flags = args[len(rest) + 1] if len(args) > len(rest) + 1 else None
            if flags and flags[0] == 'int' and flags[1] is not None:
                if flags[1] & RECEIVER_NOT_EXPORTED:
                    return
            else:
                conf = 'medium'   # flags unknown: may hold RECEIVER_NOT_EXPORTED
        self.report('dynamic_receiver_no_permission', conf, no,
                    '%s [%s: any app can send this receiver a broadcast]' % (text, how))

    @property
    def is_on_receive(self):
        return self.m['name'] == 'onReceive' and \
            self.m['desc'] == 'Landroid/content/Context;Landroid/content/Intent;'

    @property
    def ctx_class_intent(self):
        return 'Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V' \
            in self.ctx.method_text(self.m)

    def misc(self, no, text, owner, name, args):
        clip = args[0] if args else None
        if owner == 'Landroid/content/ClipData;' and name in ('newPlainText', 'newHtmlText') \
                and len(args) > 1 and args[1] and args[1][0] == 'pw':
            self.report('clipboard_sensitive', 'medium', no,
                        '%s [%s put in ClipData]' % (text, args[1][1]))
        elif owner.endswith('ClipboardManager;') and name == 'setPrimaryClip' \
                and clip and clip[0] == 'clip':
            self.report('clipboard_sensitive', 'medium', no,
                        '%s [%s copied to the clipboard]' % (text, clip[1]))
        elif owner.endswith('ClipboardManager;') and name == 'setPrimaryClip':
            if 'getPassword' in self.seen or self.sig in self.ctx.input_readers:
                self.report('clipboard_sensitive', 'medium', no, text)
        elif owner == 'Landroid/telephony/TelephonyManager;' and name in (
                'getDeviceId', 'getImei', 'getMeid', 'getSimSerialNumber', 'getSubscriberId'):
            self.report('unique_ids', 'high', no, text)
        elif owner == 'Landroid/os/Build;' and name in ('getSerial', 'getSerialNumber'):
            self.report('unique_ids', 'high', no, text)
        elif owner == 'Landroid/provider/Settings$Secure;' and name == 'getString' \
                and len(args) > 1 and args[1] and args[1][0] == 'str' and args[1][1] == 'android_id':
            self.report('unique_ids', 'high', no, text)
        elif owner in ('Ldalvik/system/DexClassLoader;', 'Ldalvik/system/PathClassLoader;',
                       'Ldalvik/system/InMemoryDexClassLoader;') and name == '<init>':
            self.report('dynamic_code_load', 'high', no, text)

    def summaries(self, callee, vals):
        for k, sinks in self.ctx.summary.get(callee, {}).items():
            if k >= len(vals):
                continue
            v = vals[k]
            for kind, cls, sno, stext in sinks:
                if _const_strength(v):
                    conf = 'low' if kind == 'pbe_pass' else 'medium'
                    self.ctx.emit(cls, SINK_KINDS[kind], conf, sno, stext)
                elif v and v[0] == 'param':
                    self.ctx.add_summary(self.sig, v[1], kind, cls, sno, stext)


class _Context:
    """State shared across methods: constant static fields, summaries, findings."""

    def __init__(self, classes):
        self.classes = classes
        self.fields = {}
        for cls in classes:
            for ref, value in cls['field_inits'].items():
                self.fields[ref] = ('str', value, 'high')
        self.writes = {}
        self.summary = {}
        self.seeded = set()
        self.findings = {}
        self.input_readers = set()
        self.js_interfaces = set()   # (file, line, text, interface class or None)
        self.sticky_actions = set()  # actions of sticky broadcasts sent by the app
        self.dyn_receivers = set()   # (receiver class, actions, permission given)
        self.target_sdk = None       # targetSdkVersion from apktool.yml, if known
        self.password_ids = {}       # resource id -> password field description
        self.ui_fields = {}          # instance field -> ('view', id) or ('pw', field)
        self.sticky_sends = set()    # (action, class, file, line, text) of sticky sends
        self.registered_actions = set()  # IntentFilter actions passed to registerReceiver

    def field_write(self, ref, value, in_clinit):
        const = value if value and value[0] in ('str', 'lit') and in_clinit else None
        self.writes.setdefault(ref, []).append(const)

    def settle_fields(self):
        for ref, values in self.writes.items():
            if all(values) and len({v[0] for v in values}) == 1:
                self.fields[ref] = values[0]
            else:
                self.fields.pop(ref, None)
        self.writes = {}

    def add_summary(self, sig, k, kind, cls, no, text):
        sinks = self.summary.setdefault(sig, {}).setdefault(k, [])
        entry = (kind, cls, no, text)
        if entry not in sinks:
            sinks.append(entry)

    @staticmethod
    def method_text(method):
        return '\n'.join(t for _, t in method['body'])

    def reads_input(self, method):
        body = self.method_text(method)
        return 'EditText;->getText' in body or 'TextView;->getText' in body \
            or '->getPassword(' in body

    def find_input_readers(self, decoded_dir):
        """Signatures of app methods that read an input field (EditText or
        TextView getText, or getPassword) directly or through up to
        INPUT_CALL_DEPTH calls to other app methods, using call_graph.py.
        Synthetic accessors such as access$000 count as one call level."""
        readers = set()
        for cls in self.classes:
            for m in cls['methods']:
                if self.reads_input(m):
                    readers.add('%s->%s(%s)%s' % (cls['name'], m['name'], m['desc'], m['ret']))
        _, reverse = call_graph.build(decoded_dir)
        level = set(readers)
        for _ in range(INPUT_CALL_DEPTH):
            level = {caller for callee in level for caller in reverse.get(callee, ())} - readers
            readers |= level
        self.input_readers = readers

    def emit(self, cls, pattern, conf, no, text):
        key = (cls['file'], no, pattern)
        cur = self.findings.get(key)
        if cur and CONFIDENCE.index(cur['confidence']) <= CONFIDENCE.index(conf):
            return
        self.findings[key] = {
            'component': _dotted(cls['name']),
            'component_type': 'class',
            'file': cls['file'],
            'line': no,
            'pattern': pattern,
            'issue': pattern,
            'cwe': PATTERNS[pattern],
            'confidence': conf,
            'evidence': text,
        }


# ---------------------------------------------------------------- class rules

def _only(method):
    return [t for _, t in _code(method['body'])]


CHECK_WORDS = ('check', 'verify')


def _always_true(code):
    """True when a boolean method has no branch and returns a register last set
    by const/4 vN, 0x1."""
    if not code or any(t.startswith(('if-', 'packed-switch', 'sparse-switch')) for t in code):
        return False
    last = code[-1].split()
    if last[0] != 'return' or len(last) < 2:
        return False
    reg = last[1]
    for text in reversed(code[:-1]):
        ops = [o.strip() for o in text.split(None, 1)[-1].split(',')]
        if ops and ops[0] == reg and not text.startswith(NO_DEST):
            return text.startswith('const/4') and ops[-1] == '0x1'
    return False


# Exception types whose handler would also catch a CertificateException.
CERT_CATCHES = ('Ljava/security/cert/CertificateException;',
                'Ljava/security/GeneralSecurityException;',
                'Ljava/lang/Exception;', 'Ljava/lang/Throwable;')
CATCH_HANDLER_RE = re.compile(r'^\.catch(?:all)?\s+(?:(\S+;)\s+)?\{(\S+)\s*\.\.\s*(\S+)\}\s+(\S+)')


def _handler_rethrows(body, label):
    """Linear scan from a catch handler label: True when a throw comes before
    the first return or goto (the caught exception, or a new one, propagates)."""
    started = False
    for _, text in body:
        if not started:
            started = text == label
            continue
        if text.startswith(('.', ':')):
            continue
        op = text.split()[0]
        if op == 'throw':
            return True
        if op.startswith(('return', 'goto')):
            return False
    return False


def _check_propagates(method):
    """P-3: True when a check*Trusted method can end by throwing, so it is not
    an empty check. Linear scan of the body (no control flow graph):
      - a throw instruction anywhere, or
      - a call to a method whose name contains 'check' or 'verify' (for
        example X509Certificate.checkValidity or a delegate trust manager)
        that is not inside a try range whose handler catches
        CertificateException (or a supertype) and then returns without
        throwing. A handler that throws again lets the exception propagate."""
    body = method['body']
    labels = {text: idx for idx, (_, text) in enumerate(body) if text.startswith(':')}
    swallowing = []
    for _, text in body:
        m = CATCH_HANDLER_RE.match(text)
        if not m or m.group(2) not in labels or m.group(3) not in labels:
            continue
        if (m.group(1) is None or m.group(1) in CERT_CATCHES) \
                and not _handler_rethrows(body, m.group(4)):
            swallowing.append((labels[m.group(2)], labels[m.group(3)]))
    for idx, _, text in _indexed_code(body):
        op = text.split()[0]
        if op == 'throw':
            return True
        if op.startswith('invoke-'):
            inv = INVOKE_RE.match(text)
            ref = METHOD_REF_RE.match(inv.group(3)) if inv else None
            if ref and any(w in ref.group(2).lower() for w in CHECK_WORDS) \
                    and not any(a <= idx <= b for a, b in swallowing):
                return True
    return False


def _class_rules(ctx, cls):
    if 'Ljavax/net/ssl/X509TrustManager;' in cls['implements']:
        # P-3: an HTTPS client never calls checkClientTrusted, so an empty one
        # is only a trust bypass when checkServerTrusted of the same class does
        # not throw either; otherwise it is reported low.
        server = [m for m in cls['methods'] if m['name'] == 'checkServerTrusted'
                  and _only(m) != ['return-void']]
        server_checks = bool(server) and all(_check_propagates(m) for m in server)
        for m in cls['methods']:
            if m['name'] not in ('checkServerTrusted', 'checkClientTrusted'):
                continue
            code = _only(m)
            if code == ['return-void']:
                if m['name'] == 'checkClientTrusted' and server_checks:
                    ctx.emit(cls, 'empty_trustmanager', 'low', m['line'],
                             '%s [checkClientTrusted is empty, but checkServerTrusted '
                             'throws on a bad chain]' % m['decl'])
                else:
                    ctx.emit(cls, 'empty_trustmanager', 'high', m['line'], m['decl'])
            elif m['name'] == 'checkServerTrusted' and code and not _check_propagates(m):
                # Has instructions, but none of them throws or calls a check.
                ctx.emit(cls, 'empty_trustmanager', 'medium', m['line'], m['decl'])
    if 'Ljavax/net/ssl/HostnameVerifier;' in cls['implements']:
        for m in cls['methods']:
            if m['name'] != 'verify' or m['ret'] != 'Z':
                continue
            code = _only(m)
            if len(code) == 2 and _always_true(code):
                ctx.emit(cls, 'hostname_not_verified', 'high', m['line'], m['decl'])
            elif _always_true(code):
                ctx.emit(cls, 'hostname_not_verified', 'medium', m['line'], m['decl'])


RECEIVER = 'Landroid/content/BroadcastReceiver;'
RESULT_CALLS = ('setResult', 'setResultData', 'setResultExtras', 'abortBroadcast')


def _receiver_priorities(decoded_dir):
    """{class descriptor: highest intent filter priority} for the receivers in
    the decoded AndroidManifest.xml."""
    path = os.path.join(decoded_dir, 'AndroidManifest.xml')
    try:
        manifest = apk.parse_manifest(path)
    except (OSError, ET.ParseError):
        return {}
    out = {}
    for comp in manifest['components']:
        if comp['type'] != 'receiver' or not comp['name']:
            continue
        values = [_int(f['priority']) for f in comp['intent_filters'] if f.get('priority')]
        values = [v for v in values if v is not None]
        if values:
            out['L%s;' % comp['name'].replace('.', '/')] = max(values)
    return out


def _is_receiver(cls, by_name):
    seen = set()
    sup = cls['super']
    while sup and sup not in seen:
        if sup == RECEIVER:
            return True
        seen.add(sup)
        sup = by_name[sup]['super'] if sup in by_name else None
    return False


def _receiver_chain(cls, by_name):
    """Descriptors of cls and its app superclasses up to BroadcastReceiver."""
    chain = {cls['name'], RECEIVER}
    sup = cls['super']
    while sup and sup not in chain:
        chain.add(sup)
        sup = by_name[sup]['super'] if sup in by_name else None
    return chain


def _result_call(method, owners=None):
    """(line, text) of the first call in method to one of RESULT_CALLS, or None.
    With owners, only an invoke-virtual on one of those class descriptors counts."""
    for no, text in _code(method['body']):
        inv = INVOKE_RE.match(text)
        ref = METHOD_REF_RE.match(inv.group(3)) if inv else None
        if not ref or ref.group(2) not in RESULT_CALLS:
            continue
        if owners is None or (inv.group(1).startswith('invoke-virtual')
                              and ref.group(1) in owners):
            return no, text
    return None


def _ordered_broadcast_rules(ctx, classes, decoded_dir):
    """Two triggers, one finding per receiver class:
    1. declared with intent filter priority > 0 and onReceive calls a result
       method on any object (the original rule);
    2. any priority, or none: onReceive invoke-virtual's a result method on the
       receiver itself, an app superclass or BroadcastReceiver. A receiver that
       changes or aborts the result takes part in an ordered broadcast chain, so a
       higher priority receiver can inject data into it (CWE-927).
    Both report at medium, so when both match the same receiver only the first
    is kept."""
    priorities = _receiver_priorities(decoded_dir)
    by_name = {c['name']: c for c in classes}
    for cls in classes:
        if not _is_receiver(cls, by_name):
            continue
        owners = _receiver_chain(cls, by_name)
        for m in cls['methods']:
            if m['name'] != 'onReceive' or m['desc'] != 'Landroid/content/Context;Landroid/content/Intent;':
                continue
            hit = _result_call(m) if priorities.get(cls['name'], 0) > 0 else None
            hit = hit or _result_call(m, owners)
            if hit:
                ctx.emit(cls, 'ordered_broadcast_priority', 'medium', *hit)


# ---------------------------------------------------------------- app rules

ANDROID_NS = '{http://schemas.android.com/apk/res/android}'
APP_COMPONENT = '(application)'

# Calls that show the app opens a network or TLS connection.
NETWORK_CALLS = ('Ljava/net/URL;->openConnection', 'Ljava/net/HttpURLConnection;->',
                 'Ljavax/net/ssl/HttpsURLConnection;->', 'Ljavax/net/ssl/SSLSocketFactory;->',
                 'Ljavax/net/ssl/SSLContext;->', 'Lokhttp3/', 'Ljava/net/Socket;-><init>')
# Bundled network libraries: their own classes do not count as app network code.
NETWORK_LIBRARIES = ('Lokhttp3/', 'Lokio/', 'Lretrofit2/')


def _invokes(method):
    """(line, text, method reference) for each invoke in method."""
    for no, text in _code(method['body']):
        if text.startswith('invoke-'):
            m = INVOKE_RE.match(text)
            if m:
                yield no, text, m.group(3)


def _emit_app(ctx, rel, no, pattern, conf, evidence):
    """Record an application level finding (not tied to one class)."""
    key = (rel, no, pattern)
    cur = ctx.findings.get(key)
    if cur and CONFIDENCE.index(cur['confidence']) <= CONFIDENCE.index(conf):
        return
    ctx.findings[key] = {
        'component': APP_COMPONENT,
        'component_type': 'application',
        'file': rel,
        'line': no,
        'pattern': pattern,
        'issue': pattern,
        'cwe': PATTERNS[pattern],
        'confidence': conf,
        'evidence': evidence,
    }


def _line_of(path, needle):
    """1-based number of the first line of path containing needle (1 if none)."""
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for no, raw in enumerate(f, 1):
                if needle in raw:
                    return no
    except OSError:
        pass
    return 1


def _network_call(classes):
    """(class, line, text) of the first network or TLS call in app code, or None."""
    for cls in classes:
        if cls['name'].startswith(NETWORK_LIBRARIES):
            continue
        for m in cls['methods']:
            for no, text, ref in _invokes(m):
                if ref.startswith(NETWORK_CALLS):
                    return cls, no, text
    return None


def _pins_in_code(classes):
    """True when app code pins certificates itself: okhttp3 CertificatePinner,
    or a KeyStore filled with setCertificateEntry handed to
    TrustManagerFactory.init (the idiom of the Android training docs)."""
    refs = set()
    for cls in classes:
        if cls['name'].startswith(NETWORK_LIBRARIES):
            continue
        for m in cls['methods']:
            for _, _, ref in _invokes(m):
                refs.add(ref.split('(')[0])
    if any(r.startswith('Lokhttp3/CertificatePinner') for r in refs):
        return True
    return 'Ljava/security/KeyStore;->setCertificateEntry' in refs and \
        'Ljavax/net/ssl/TrustManagerFactory;->init' in refs


def _pinning_rules(ctx, classes, decoded_dir):
    """certificate_pinning_missing: one application level finding when the app
    makes network connections but neither its network security config nor its
    code pins certificates. Limits: only the config file and two common code
    pinning idioms are recognised; pins set up through reflection, native code
    or other libraries are missed (the app is then flagged). A config with a
    pin-set for one domain counts as pinned even if other hosts are not."""
    hit = _network_call(classes)
    if hit is None or _pins_in_code(classes):
        return
    manifest_path = os.path.join(decoded_dir, 'AndroidManifest.xml')
    try:
        app = ET.parse(manifest_path).getroot().find('application')
    except (OSError, ET.ParseError):
        return
    if app is None:
        return
    ref = app.get(ANDROID_NS + 'networkSecurityConfig') or ''
    name = ref[len('@xml/'):] if ref.startswith('@xml/') else 'network_security_config'
    rel = 'res/xml/%s.xml' % name
    path = os.path.join(decoded_dir, 'res', 'xml', name + '.xml')
    call = 'network call %s' % hit[2]
    if os.path.isfile(path):
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError:
            return
        for dc in root.iter('domain-config'):
            for pin_set in dc.findall('pin-set'):
                if pin_set.find('pin') is not None:
                    return
        _emit_app(ctx, rel, _line_of(path, '<network-security-config'),
                  'certificate_pinning_missing', 'high',
                  '%s has no pin-set in any domain-config; %s' % (rel, call))
        return
    cleartext = app.get(ANDROID_NS + 'usesCleartextTraffic')
    if cleartext == 'false':
        return
    _emit_app(ctx, 'AndroidManifest.xml', _line_of(manifest_path, '<application'),
              'certificate_pinning_missing', 'high',
              'no network security config, usesCleartextTraffic %s; %s'
              % ('="%s"' % cleartext if cleartext is not None else 'unset', call))


FRAGMENT_LOADERS = ('Landroid/app/Fragment;->instantiate',
                    'Landroid/support/v4/app/Fragment;->instantiate',
                    'Landroidx/fragment/app/Fragment;->instantiate')
INTENT_READS = TAINT_SOURCES


def _outer(name):
    """Descriptor of the outermost class: La/B$1; -> La/B;"""
    return name.split('$', 1)[0].rstrip(';') + ';'


def _preference_activity_chain(cls, by_name):
    """App classes from cls up to the one whose .super names a PreferenceActivity,
    or None when cls is not a PreferenceActivity."""
    chain, cur = [], cls
    while cur is not None and cur not in chain:
        chain.append(cur)
        if cur['super'] and 'PreferenceActivity' in cur['super']:
            return chain
        cur = by_name.get(cur['super'])
    return None


def _fragment_factories(classes):
    """Signatures of app methods that return a Fragment and build it from a class
    name (Class.forName or Fragment.instantiate)."""
    out = set()
    for cls in classes:
        for m in cls['methods']:
            if not m['ret'].endswith('Fragment;'):
                continue
            refs = [ref for _, _, ref in _invokes(m)]
            if any(r.startswith(('Ljava/lang/Class;->forName',) + FRAGMENT_LOADERS) for r in refs):
                out.add('%s->%s(%s)%s' % (cls['name'], m['name'], m['desc'], m['ret']))
    return out


def _fragment_rules(ctx, classes, decoded_dir):
    """fragment_injection (CWE-470). Limits: a PreferenceActivity's
    isValidFragment that has branches is trusted; the fragment name rule does
    not follow the name from the intent to the loader (it only looks for an
    intent read and the absence of any *valid* method in the same outer class),
    and checks done inside the loader itself are not counted, since they
    usually only pick among fragments instead of rejecting names."""
    try:
        target = apk._sdk_info(decoded_dir).get('target_sdk')
    except OSError:
        target = None
    by_name = {c['name']: c for c in classes}
    for cls in classes:
        chain = _preference_activity_chain(cls, by_name)
        if not chain:
            continue
        checks = [m for c in chain for m in c['methods'] if m['name'] == 'isValidFragment']
        if not checks:
            conf = 'medium' if target is not None and target >= 19 else 'high'
            ctx.emit(cls, 'fragment_injection', conf, cls['super_line'] or 1,
                     '.super ' + cls['super'])
        elif checks[0] in cls['methods'] and _always_true(_only(checks[0])):
            ctx.emit(cls, 'fragment_injection', 'medium', checks[0]['line'], checks[0]['decl'])
    factories = _fragment_factories(classes)
    groups = {}
    for cls in classes:
        groups.setdefault(_outer(cls['name']), []).append(cls)
    for members in groups.values():
        reads, validated, calls = False, False, []
        for cls in members:
            for m in cls['methods']:
                if 'valid' in m['name'].lower():
                    validated = True
                for no, text, ref in _invokes(m):
                    callee = ref.split('->', 1)[-1].split('(')[0]
                    if callee in INTENT_READS:
                        reads = True
                    if 'valid' in callee.lower():
                        validated = True
                    if ref in factories or ref.startswith(FRAGMENT_LOADERS):
                        calls.append((cls, no, text))
        if reads and not validated:
            for cls, no, text in calls:
                ctx.emit(cls, 'fragment_injection', 'medium', no, text)


JS_ANNOTATION = 'Landroid/webkit/JavascriptInterface;'
FILE_CLASSES = ('Ljava/io/File;', 'Ljava/io/FileInputStream;', 'Ljava/io/FileOutputStream;',
                'Ljava/io/FileReader;', 'Ljava/io/FileWriter;', 'Ljava/io/RandomAccessFile;')
FILE_CALLS = ('openFileInput', 'openFileOutput', 'deleteFile')
RESOLVER_CALLS = ('query', 'insert', 'update', 'delete', 'bulkInsert')
INTENT_SENDS = CONTEXT_START + ('sendBroadcast', 'sendOrderedBroadcast', 'sendStickyBroadcast',
                                'sendBroadcastAsUser')


def _js_annotated(method):
    return any(t.startswith('.annotation') and JS_ANNOTATION in t for _, t in method['body'])


def _sensitive_call(ref):
    """'file', 'network', 'database' or 'intent' when the method reference is a
    sensitive operation, else None."""
    m = METHOD_REF_RE.match(ref)
    if not m:
        return None
    owner, name = m.group(1), m.group(2)
    if owner in FILE_CLASSES or name in FILE_CALLS:
        return 'file'
    if ref.startswith(NETWORK_CALLS) or owner == 'Ljava/net/Socket;':
        return 'network'
    if owner == 'Landroid/database/sqlite/SQLiteDatabase;' or (
            owner in ('Landroid/content/ContentResolver;', 'Landroid/content/ContentProviderClient;')
            and name in RESOLVER_CALLS):
        return 'database'
    if name in INTENT_SENDS:
        return 'intent'
    return None


def _sensitive(method, by_name, depth=1):
    """Kind of the first sensitive operation in method, following up to depth
    calls into app methods (looked up by owner, name and descriptor; virtual
    dispatch to subclasses is not followed)."""
    for _, _, ref in _invokes(method):
        kind = _sensitive_call(ref)
        if kind:
            return kind
        m = METHOD_REF_RE.match(ref)
        if depth and m and m.group(1) in by_name:
            for callee in by_name[m.group(1)]['methods']:
                if callee['name'] == m.group(2) and callee['desc'] == m.group(3) \
                        and callee is not method:
                    kind = _sensitive(callee, by_name, depth - 1)
                    if kind:
                        return kind
    return None


def _js_interface_rules(ctx, classes, decoded_dir):
    """webview_js_interface (CWE-749): sensitive methods reachable from
    JavaScript through addJavascriptInterface. Limits: the interface object is
    resolved within one method only; a sensitive call reached through more than
    one app call level, reflection or a field holding a helper is missed, and a
    method that checks its arguments before acting is still reported."""
    if not ctx.js_interfaces:
        return
    try:
        min_sdk = apk._sdk_info(decoded_dir).get('min_sdk')
    except OSError:
        min_sdk = None
    all_public = min_sdk is not None and min_sdk < 17
    by_name = {c['name']: c for c in classes}
    targets, unresolved = set(), False
    for _, _, _, t in ctx.js_interfaces:
        if t in by_name:
            targets.add(t)
        else:
            unresolved = True
    if unresolved:
        targets |= {c['name'] for c in classes if any(_js_annotated(m) for m in c['methods'])}
    done = set()
    for t in sorted(targets):
        cls, seen = by_name.get(t), set()
        while cls is not None and cls['name'] not in seen:   # the class and its app superclasses
            seen.add(cls['name'])
            for m in cls['methods']:
                key = (cls['name'], m['line'])
                if key in done or m['static'] or m['name'].startswith('<') \
                        or ' public ' not in ' ' + m['decl'] + ' ':
                    continue
                if not (_js_annotated(m) or all_public):
                    continue
                done.add(key)
                if _sensitive(m, by_name):
                    ctx.emit(cls, 'webview_js_interface', 'high', m['line'], m['decl'])
            cls = by_name.get(cls['super'])


STICKY_CHECKS = ('isInitialStickyBroadcast', 'checkCallingPermission',
                 'checkCallingOrSelfPermission', 'enforceCallingPermission',
                 'enforceCallingOrSelfPermission')
COMPARES = ('equals', 'equalsIgnoreCase', 'contentEquals', 'matches', 'compareTo',
            'isEmpty', 'startsWith', 'endsWith', 'contains')


def _checks_broadcast(method):
    """True when onReceive checks the broadcast before acting: a STICKY_CHECKS
    call, getAction compared with a COMPARES call, or an extra (get*Extra,
    getExtras, Bundle get*) that is null checked (if-eqz / if-nez) or passed to a
    COMPARES call (including TextUtils.isEmpty). Branch order is not modelled:
    a check anywhere in the method counts."""
    extras, pending = set(), None
    for no, text in _code(method['body']):
        op = text.split()[0]
        ops = [o.strip() for o in text.split(None, 1)[-1].split(',')]
        if op.startswith('move-result'):
            if pending == 'extra':
                extras.add(ops[0])
            elif pending == 'action':
                extras.add(ops[0])
            pending = None
            continue
        pending = None
        if op.startswith('invoke-'):
            inv = INVOKE_RE.match(text)
            ref = METHOD_REF_RE.match(inv.group(3)) if inv else None
            if not ref:
                continue
            owner, name = ref.group(1), ref.group(2)
            regs = _regs(inv.group(2))
            if name in STICKY_CHECKS:
                return True
            if name in COMPARES and (set(regs) & extras):
                return True
            if owner == 'Landroid/content/Intent;' and name == 'getAction':
                pending = 'action'
            elif (owner == 'Landroid/content/Intent;' and (name.endswith('Extra') or name == 'getExtras')) \
                    or (owner == 'Landroid/os/Bundle;' and name.startswith('get')):
                pending = 'extra'
        elif op in ('if-eqz', 'if-nez') and ops[0] in extras:
            return True
        elif op.startswith('move') and len(ops) > 1 and ops[1] in extras:
            extras.add(ops[0])
    return False


def _sticky_receiver_rules(ctx, classes, decoded_dir):
    """sticky_broadcast_receiver (CWE-927): receivers in this app that consume
    a sticky broadcast the app sends without checking it. Limits: only actions
    given as constant strings are matched, receivers registered by another app
    are out of reach, and receivers whose class the register model cannot
    resolve at the registerReceiver call are missed."""
    actions = ctx.sticky_actions
    if not actions:
        return
    targets = set()
    try:
        manifest = apk.parse_manifest(os.path.join(decoded_dir, 'AndroidManifest.xml'))
    except (OSError, ET.ParseError):
        manifest = {'components': []}
    for comp in manifest['components']:
        if comp['type'] != 'receiver' or not comp['name'] or comp.get('permission'):
            continue
        if any(a in actions for f in comp['intent_filters'] for a in f['actions']):
            targets.add('L%s;' % comp['name'].replace('.', '/'))
    for t, acts, perm in ctx.dyn_receivers:
        if not perm and set(acts) & actions:
            targets.add(t)
    by_name = {c['name']: c for c in classes}
    for t in sorted(targets):
        cls = by_name.get(t)
        if cls is None:
            continue
        for m in cls['methods']:
            if m['name'] == 'onReceive' and m['desc'] == 'Landroid/content/Context;Landroid/content/Intent;' \
                    and not _checks_broadcast(m):
                ctx.emit(cls, 'sticky_broadcast_receiver', 'medium', m['line'], m['decl'])


# ---------------------------------------------------------------- layouts

PASSWORD_INPUT_TYPES = ('textPassword', 'numberPassword', 'textVisiblePassword',
                        'textWebPassword')


def _resource_ids(decoded_dir):
    """{id name: resource int} from res/values/public.xml (type="id")."""
    path = os.path.join(decoded_dir, 'res', 'values', 'public.xml')
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return {}
    out = {}
    for e in root.iter('public'):
        if e.get('type') == 'id' and e.get('name') and e.get('id'):
            n = _int(e.get('id'))
            if n is not None:
                out[e.get('name')] = n
    return out


def _password_fields(decoded_dir):
    """{resource int: description} for the views in res/layout*/*.xml with an
    android:inputType containing one of PASSWORD_INPUT_TYPES, or
    android:password="true". The description names the id, the layout file and
    the attribute, for the finding evidence."""
    res = os.path.join(decoded_dir, 'res')
    if not os.path.isdir(res):
        return {}
    ids, out = None, {}
    for entry in sorted(os.listdir(res)):
        folder = os.path.join(res, entry)
        if not entry.startswith('layout') or not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            if not name.endswith('.xml'):
                continue
            try:
                root = ET.parse(os.path.join(folder, name)).getroot()
            except (OSError, ET.ParseError):
                continue
            for e in root.iter():
                input_type = e.get(ANDROID_NS + 'inputType') or ''
                kinds = [t for t in input_type.split('|') if t.strip() in PASSWORD_INPUT_TYPES]
                if kinds:
                    how = 'inputType %s' % input_type
                elif (e.get(ANDROID_NS + 'password') or '').lower() == 'true':
                    how = 'password="true"'
                else:
                    continue
                ref = e.get(ANDROID_NS + 'id') or ''
                id_name = ref.split('/', 1)[1] if ref.startswith(('@id/', '@+id/')) else None
                if not id_name:
                    continue
                if ids is None:
                    ids = _resource_ids(decoded_dir)
                n = ids.get(id_name)
                if n is not None and n not in out:
                    out[n] = "'%s' (res/%s/%s, %s)" % (id_name, entry, name, how)
    return out


# ------------------------------------------------- rules from the miss analysis
# A4-2 (docs/notes/miss-analysis.md). Each rule reads one method at a time with
# its own small register model; branches are not followed.

CATCH_RE = re.compile(r'^\.catch(all)?\s+(?:(\S+;)\s+)?\{(\S+)\s*\.\.\s*(\S+)\}')
NPE_CATCHES = ('Ljava/lang/NullPointerException;', 'Ljava/lang/RuntimeException;',
               'Ljava/lang/Exception;', 'Ljava/lang/Throwable;')
NULL_GUARDS = ('isEmpty', 'equals', 'requireNonNull', 'isNull', 'nonNull', 'hasExtra')


def _indexed_code(body):
    """(index in body, line, text) for the instructions of a method body (as
    _code, but keeping the position so try ranges can be matched)."""
    end = None
    for idx, (no, text) in enumerate(body):
        if end:
            if text == end:
                end = None
            continue
        if text.startswith(BLOCK_STARTS):
            end = '.end ' + text.split()[0][1:]
            continue
        if text.startswith(('.', ':')):
            continue
        yield idx, no, text


def _catch_ranges(body):
    """[(start index, end index, exception type or None for .catchall)]."""
    labels, catches = {}, []
    for idx, (_, text) in enumerate(body):
        if text.startswith(':'):
            labels[text] = idx
        elif text.startswith('.catch'):
            m = CATCH_RE.match(text)
            if m:
                catches.append((m.group(3), m.group(4), None if m.group(1) else m.group(2)))
    return [(labels[a], labels[b], t) for a, b, t in catches if a in labels and b in labels]


def _operand_regs(text):
    return [o.strip() for o in text.split(None, 1)[-1].split(',')] if ' ' in text else []


def _writes(text):
    """Register written by a plain (non-invoke) instruction, or None."""
    op = text.split()[0]
    if op.startswith(('invoke-', 'move-exception')) or op.startswith(NO_DEST):
        return None
    ops = _operand_regs(text)
    return ops[0] if ops else None


def _exported_classes(decoded_dir):
    """Descriptors of the exported components in the decoded manifest."""
    try:
        manifest = apk.parse_manifest(os.path.join(decoded_dir, 'AndroidManifest.xml'),
                                      apk._sdk_info(decoded_dir))
    except (OSError, ET.ParseError):
        return set()
    return {'L%s;' % c['name'].replace('.', '/') for c in manifest['components']
            if c['exported'] and c['name'] and c['type'] != 'activity-alias'}


def _null_derefs(method):
    """(line, text) of calls on the result of Intent.getStringExtra with no
    null test (if-eqz / if-nez) of that register before them and outside any
    try range that catches NullPointerException or a supertype (or catchall).
    Passing the value to an isEmpty / equals / requireNonNull style call counts
    as a check. Each extra value is reported at its first dereference only."""
    body = method['body']
    ranges = _catch_ranges(body)
    tracked, pending, hits = set(), False, []
    for idx, no, text in _indexed_code(body):
        op = text.split()[0]
        if op.startswith('move-result'):
            dest = _operand_regs(text)[0]
            (tracked.add if pending else tracked.discard)(dest)
            pending = False
            continue
        pending = False
        if op.startswith('invoke-'):
            inv = INVOKE_RE.match(text)
            ref = METHOD_REF_RE.match(inv.group(3)) if inv else None
            if not ref:
                continue
            regs = _regs(inv.group(2))
            owner, name = ref.group(1), ref.group(2)
            if owner == 'Landroid/content/Intent;' and name == 'getStringExtra':
                pending = True
                continue
            if any(g in name for g in NULL_GUARDS):
                tracked -= set(regs)
                continue
            if not op.startswith('invoke-static') and regs and regs[0] in tracked:
                tracked.discard(regs[0])
                if not any(a <= idx <= b and (t is None or t in NPE_CATCHES) for a, b, t in ranges):
                    hits.append((no, text))
            continue
        ops = _operand_regs(text)
        if op in ('if-eqz', 'if-nez') and ops:
            tracked.discard(ops[0])
        elif op.startswith('move') and len(ops) > 1:
            (tracked.add if ops[1] in tracked else tracked.discard)(ops[0])
        else:
            dest = _writes(text)
            if dest:
                tracked.discard(dest)
    return hits


def _null_deref_rules(ctx, classes, decoded_dir):
    """null_deref_intent_extra (CWE-476): a string extra of the incoming Intent
    dereferenced without a null check, in an exported component or one of its
    inner classes, so any app can crash it by sending the Intent without the
    extra. Limits: checks made in another method (or through getExtras() !=
    null on the bundle) and a try range around the caller are not seen."""
    exported = _exported_classes(decoded_dir)
    if not exported:
        return
    for cls in classes:
        if _outer(cls['name']) not in exported:
            continue
        for m in cls['methods']:
            for no, text in _null_derefs(m):
                ctx.emit(cls, 'null_deref_intent_extra', 'medium', no, text)


KEYSTORE_SET_ENTRY = ('Ljava/security/KeyStore;->setEntry(Ljava/lang/String;'
                      'Ljava/security/KeyStore$Entry;Ljava/security/KeyStore$ProtectionParameter;)V')


def _keystore_rules(ctx, classes):
    """keystore_entry_unprotected (CWE-922): KeyStore.setEntry whose
    ProtectionParameter register holds the constant null, so the entry is
    stored without a password. KeyStore.store(out, null) is not used as a
    signal (the Secure Ghera app does it too)."""
    for cls in classes:
        for m in cls['methods']:
            nulls = set()
            for no, text in _code(m['body']):
                op = text.split()[0]
                if op.startswith('invoke-'):
                    inv = INVOKE_RE.match(text)
                    regs = _regs(inv.group(2)) if inv else []
                    if inv and inv.group(3) == KEYSTORE_SET_ENTRY and len(regs) == 4 \
                            and regs[3] in nulls:
                        ctx.emit(cls, 'keystore_entry_unprotected', 'medium', no, text)
                    continue
                ops = _operand_regs(text)
                dest = _writes(text)
                if not dest:
                    continue
                if op in ('const/4', 'const/16', 'const') and _int(ops[-1]) == 0:
                    nulls.add(dest)
                elif op.startswith('move') and not op.startswith('move-result') \
                        and len(ops) > 1 and ops[1] in nulls:
                    nulls.add(dest)
                else:
                    nulls.discard(dest)


SERVER_SOCKET_INITS = ('Ljava/net/ServerSocket;-><init>(I)V', 'Ljava/net/ServerSocket;-><init>(II)V')
PEER_CHECKS = ('Ljava/net/Socket;->getInetAddress', 'Ljava/net/Socket;->getRemoteSocketAddress',
               'Ljava/net/Socket;->getPort')


def _server_socket_rules(ctx, classes):
    """server_socket_no_peer_check (CWE-940): a method that opens a
    ServerSocket on all interfaces (port only, or port and backlog), accepts a
    connection and reads or writes its streams without asking who the peer is
    (Socket.getInetAddress, getRemoteSocketAddress or getPort). Limits: the
    accept and the stream use must be in the same method, and whether a peer
    check is sound (Ghera's Secure app compares a reverse DNS name) is not
    judged."""
    for cls in classes:
        for m in cls['methods']:
            calls = list(_invokes(m))
            init = next(((no, text) for no, text, ref in calls if ref in SERVER_SOCKET_INITS), None)
            if init is None:
                continue
            refs = [ref for _, _, ref in calls]
            if 'Ljava/net/ServerSocket;->accept()Ljava/net/Socket;' not in refs:
                continue
            if not any(r.startswith(('Ljava/net/Socket;->getOutputStream',
                                     'Ljava/net/Socket;->getInputStream')) for r in refs):
                continue
            if any(r.startswith(PEER_CHECKS) for r in refs):
                continue
            ctx.emit(cls, 'server_socket_no_peer_check', 'medium', *init)


EXTERNAL_DIRS = ('getExternalFilesDir', 'getExternalFilesDirs', 'getExternalCacheDir',
                 'getExternalCacheDirs', 'getExternalMediaDirs', 'getExternalStorageDirectory',
                 'getExternalStoragePublicDirectory')
FILE_PATH_CALLS = ('getAbsolutePath', 'getPath', 'getCanonicalPath', 'toString',
                   'getAbsoluteFile', 'getCanonicalFile')
FILE_STREAMS = ('Ljava/io/FileInputStream;', 'Ljava/io/FileReader;', 'Ljava/io/FileOutputStream;',
                'Ljava/io/FileWriter;', 'Ljava/io/RandomAccessFile;')


def _external_storage_rules(ctx, classes):
    """external_storage_io (CWE-922): a file under shared external storage
    (getExternalFilesDir, getExternalCacheDir, Environment
    getExternalStorageDirectory / getExternalStoragePublicDirectory and the
    array forms) opened with FileInputStream / FileReader (other apps can plant
    the data) or FileOutputStream / FileWriter (other apps can read it). On API
    27 any app with the storage permission can read and write these folders.
    The path is followed in one method through File(File, String),
    File(String), getAbsolutePath and similar, StringBuilder and String
    concatenation. Whether the data is sensitive is not judged."""
    for cls in classes:
        for m in cls['methods']:
            ext, pending = set(), False
            for no, text in _code(m['body']):
                op = text.split()[0]
                if op.startswith('move-result'):
                    dest = _operand_regs(text)[0]
                    (ext.add if pending else ext.discard)(dest)
                    pending = False
                    continue
                pending = False
                if op.startswith('invoke-'):
                    inv = INVOKE_RE.match(text)
                    ref = METHOD_REF_RE.match(inv.group(3)) if inv else None
                    if not ref:
                        continue
                    owner, name = ref.group(1), ref.group(2)
                    regs = _regs(inv.group(2))
                    static = op.startswith('invoke-static')
                    recv = regs[0] if regs and not static else None
                    args = regs if static else regs[1:]
                    from_ext = any(a in ext for a in args)
                    if name in EXTERNAL_DIRS:
                        pending = True
                    elif name == '<init>' and owner in FILE_STREAMS:
                        if args and args[0] in ext:
                            ctx.emit(cls, 'external_storage_io', 'medium', no, text)
                    elif name == '<init>' and owner in ('Ljava/io/File;', 'Ljava/lang/StringBuilder;'):
                        if recv:
                            (ext.add if args and args[0] in ext else ext.discard)(recv)
                    elif owner == 'Ljava/io/File;' and name in FILE_PATH_CALLS:
                        pending = recv in ext
                    elif owner == 'Ljava/lang/StringBuilder;' and name == 'append':
                        if from_ext:
                            ext.add(recv)
                        pending = recv in ext
                    elif owner == 'Ljava/lang/StringBuilder;' and name == 'toString':
                        pending = recv in ext
                    elif owner == 'Ljava/lang/String;' and name in ('concat', 'valueOf'):
                        pending = from_ext or recv in ext
                    continue
                ops = _operand_regs(text)
                dest = _writes(text)
                if not dest:
                    continue
                if (op.startswith('aget') or op.startswith('move')) and len(ops) > 1 \
                        and ops[1] in ext:
                    ext.add(dest)
                else:
                    ext.discard(dest)


SSL_ERROR_DESC = 'Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;'
OVERRIDE_DESCS = ('Landroid/webkit/WebView;Ljava/lang/String;',
                  'Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;')
BRANCHES = ('if-', 'packed-switch', 'sparse-switch')


def _always_false(code):
    """True when a boolean method has no branch, one return, and returns a
    register last set by const/4 vN, 0x0."""
    if not code or any(t.startswith(BRANCHES) for t in code):
        return False
    if sum(1 for t in code if t.startswith('return')) != 1:
        return False
    last = code[-1].split()
    if last[0] != 'return' or len(last) < 2:
        return False
    for text in reversed(code[:-1]):
        if _writes(text) == last[1]:
            return text.startswith('const/4') and _operand_regs(text)[-1] == '0x0'
    return False


def _webview_client_rules(ctx, classes):
    """webview_ssl_proceed (CWE-295): onReceivedSslError(WebView,
    SslErrorHandler, SslError) that calls SslErrorHandler.proceed(), high when
    no branch comes before the call (every certificate error is accepted),
    medium otherwise (the condition is not evaluated).
    webview_override_allows_all (CWE-829, low): shouldOverrideUrlLoading
    (either overload) that is branch-free and returns false, so the WebView
    loads whatever URL a page navigates to. Returning false is also what a
    client that does not override the method does, so this is a weak signal:
    it flags an override that checks nothing."""
    for cls in classes:
        for m in cls['methods']:
            if m['name'] == 'onReceivedSslError' and m['desc'] == SSL_ERROR_DESC:
                branched = False
                for no, text in _code(m['body']):
                    if text.startswith(BRANCHES):
                        branched = True
                    elif text.startswith('invoke-') and \
                            'Landroid/webkit/SslErrorHandler;->proceed()V' in text:
                        ctx.emit(cls, 'webview_ssl_proceed', 'medium' if branched else 'high',
                                 no, text)
                        break
            elif m['name'] == 'shouldOverrideUrlLoading' and m['desc'] in OVERRIDE_DESCS \
                    and m['ret'] == 'Z' and _always_false(_only(m)):
                ctx.emit(cls, 'webview_override_allows_all', 'low', m['line'], m['decl'])


# ---------------------------------------------------------------- entry point

def _target_sdk(decoded_dir):
    """targetSdkVersion from apktool.yml, else from <uses-sdk> in the decoded
    AndroidManifest.xml, else None."""
    target = apk._sdk_info(decoded_dir).get('target_sdk')
    if target is None:
        try:
            target = apk.parse_manifest(os.path.join(decoded_dir, 'AndroidManifest.xml'))                 .get('target_sdk')
        except (OSError, ET.ParseError):
            target = None
    return target


def analyze(decoded_dir):
    """Return the code findings for the apktool output folder `decoded_dir`."""
    classes = [c for c in (_parse_class(p, decoded_dir) for p in _class_files(decoded_dir)) if c]
    ctx = _Context(classes)
    ctx.target_sdk = _target_sdk(decoded_dir)
    ctx.password_ids = _password_fields(decoded_dir)
    ctx.find_input_readers(decoded_dir)
    for _ in range(PASSES):
        ctx.findings = {}
        for cls in classes:
            for method in cls['methods']:
                _Method(ctx, cls, method).run()
        ctx.settle_fields()
    for cls in classes:
        _class_rules(ctx, cls)
    _ordered_broadcast_rules(ctx, classes, decoded_dir)
    _pinning_rules(ctx, classes, decoded_dir)
    _fragment_rules(ctx, classes, decoded_dir)
    _js_interface_rules(ctx, classes, decoded_dir)
    _sticky_receiver_rules(ctx, classes, decoded_dir)
    _null_deref_rules(ctx, classes, decoded_dir)
    _keystore_rules(ctx, classes)
    _server_socket_rules(ctx, classes)
    _external_storage_rules(ctx, classes)
    _webview_client_rules(ctx, classes)
    return sorted(ctx.findings.values(), key=lambda f: (f['file'], f['line'], f['pattern']))


def broadcast_actions(decoded_dir):
    """Sticky broadcasts the app sends and broadcast actions it listens for,
    for the two-APK check in surface.py (A3-1):
      {'sticky': [{action, component, file, line, evidence}],
       'receivers': {action: [where]}}
    sticky lists sendSticky*Broadcast calls whose Intent action is a constant
    string (new Intent("...") or setAction("...")). receivers maps each action
    of a manifest <receiver> intent filter ('manifest <receiver> NAME') or of an
    IntentFilter built from constant strings and passed to registerReceiver
    ('registerReceiver') to where it was seen."""
    classes = [c for c in (_parse_class(p, decoded_dir) for p in _class_files(decoded_dir)) if c]
    ctx = _Context(classes)
    for _ in range(PASSES):
        ctx.findings = {}
        for cls in classes:
            for method in cls['methods']:
                _Method(ctx, cls, method).run()
        ctx.settle_fields()
    receivers = {}
    try:
        manifest = apk.parse_manifest(os.path.join(decoded_dir, 'AndroidManifest.xml'))
    except (OSError, ET.ParseError):
        manifest = {'components': []}
    for comp in manifest['components']:
        if comp['type'] == 'receiver':
            for f in comp['intent_filters']:
                for a in f['actions']:
                    if a:
                        receivers.setdefault(a, []).append('manifest <receiver> %s' % comp['name'])
    for a in sorted(ctx.registered_actions):
        receivers.setdefault(a, []).append('registerReceiver')
    sticky = [{'action': a, 'component': _dotted(c), 'file': f, 'line': no, 'evidence': text}
              for a, c, f, no, text in sorted(ctx.sticky_sends)]
    return {'sticky': sticky, 'receivers': receivers}
