"""Decode an APK with apktool and read its AndroidManifest.xml.

decode(apk_path) returns a dict:
  package               manifest package name (string)
  permissions           names from <uses-permission> (and <uses-permission-sdk-23>)
  declared_permissions  [{name, protectionLevel}] from <permission>
  components            [{name, type, exported, intent_filters, permission, ...}]
  min_sdk, target_sdk   from apktool.yml (int or None)
  application           application attributes the surface rules use

Each component dict has:
  name            fully qualified class name
  type            activity, activity-alias, service, receiver or provider
  exported        bool, with Android's default applied when the attribute is absent
  exported_attr   the raw android:exported value ("true", "false" or None)
  intent_filters  [{actions, categories, data, priority}]
  permission      android:permission, or the application permission when the
                  component has none (None when neither is set)
  For providers also: read_permission, write_permission, grant_uri_permissions,
  path_permissions [{path, pathPrefix, pathPattern, permission, readPermission,
  writePermission}] and authorities.

apktool is downloaded to tools/apktool.jar on first use (latest stable GitHub
release, checked against the SHA-256 digest GitHub publishes for the asset).
Java comes from JAVA_HOME, then C:\\Android\\jdk8, then PATH.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APKTOOL_JAR = os.path.join(ROOT, 'tools', 'apktool.jar')
RELEASES_API = 'https://api.github.com/repos/iBotPeaches/Apktool/releases/latest'
ANDROID_NS = 'http://schemas.android.com/apk/res/android'
COMPONENT_TAGS = ('activity', 'activity-alias', 'service', 'receiver', 'provider')


class ApkError(Exception):
    pass


def _a(elem, attr):
    """android:<attr> of an element, or None."""
    return elem.get('{%s}%s' % (ANDROID_NS, attr))


def ensure_apktool(jar=APKTOOL_JAR):
    """Download the latest stable apktool jar to `jar` if it is not there yet."""
    if os.path.exists(jar):
        return jar
    req = urllib.request.Request(RELEASES_API, headers={'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        release = json.load(r)
    if release.get('prerelease') or release.get('draft'):
        raise ApkError('latest apktool release is not stable: %s' % release.get('tag_name'))
    assets = [a for a in release.get('assets', []) if re.fullmatch(r'apktool_[\d.]+\.jar', a['name'])]
    if not assets:
        raise ApkError('no apktool jar in release %s' % release.get('tag_name'))
    asset = assets[0]
    os.makedirs(os.path.dirname(jar), exist_ok=True)
    tmp = jar + '.part'
    with urllib.request.urlopen(asset['browser_download_url'], timeout=300) as r, open(tmp, 'wb') as f:
        shutil.copyfileobj(r, f)
    digest = asset.get('digest') or ''
    if digest.startswith('sha256:'):
        with open(tmp, 'rb') as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        if actual != digest.split(':', 1)[1]:
            os.remove(tmp)
            raise ApkError('apktool jar SHA-256 mismatch: %s != %s' % (actual, digest))
    os.replace(tmp, jar)
    return jar


def find_java():
    exe = 'java.exe' if os.name == 'nt' else 'java'
    for home in (os.environ.get('JAVA_HOME'), r'C:\Android\jdk8'):
        if home:
            cand = os.path.join(home, 'bin', exe)
            if os.path.exists(cand):
                return cand
    found = shutil.which('java')
    if not found:
        raise ApkError('java not found: set JAVA_HOME or put java on PATH')
    return found


def run_apktool(apk_path, out_dir):
    """java -jar tools/apktool.jar d <apk> -o <out_dir> -f"""
    jar = ensure_apktool()
    cmd = [find_java(), '-jar', jar, 'd', apk_path, '-o', out_dir, '-f']
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise ApkError('apktool failed (exit %d): %s' % (r.returncode, (r.stderr or r.stdout).strip()))


def _sdk_info(decoded_dir):
    """minSdkVersion and targetSdkVersion from apktool.yml (no YAML library needed)."""
    path = os.path.join(decoded_dir, 'apktool.yml')
    info = {'min_sdk': None, 'target_sdk': None}
    if os.path.exists(path):
        with open(path, encoding='utf-8') as f:
            text = f.read()
        for key, field in (('minSdkVersion', 'min_sdk'), ('targetSdkVersion', 'target_sdk')):
            m = re.search(r"^\s*%s:\s*'?(\d+)'?" % key, text, re.M)
            if m:
                info[field] = int(m.group(1))
    return info


def _intent_filters(elem):
    filters = []
    for f in elem.findall('intent-filter'):
        data = []
        for d in f.findall('data'):
            data.append({k.split('}', 1)[1]: v for k, v in d.attrib.items() if k.startswith('{%s}' % ANDROID_NS)})
        filters.append({
            'actions': [_a(x, 'name') for x in f.findall('action')],
            'categories': [_a(x, 'name') for x in f.findall('category')],
            'data': data,
            'priority': _a(f, 'priority'),
        })
    return filters


def _default_exported(tag, filters, target_sdk):
    # Providers were exported by default when targetSdkVersion < 17.
    if tag == 'provider':
        return target_sdk is not None and target_sdk < 17
    # Other components: exported by default when they have an intent filter.
    return bool(filters)


def _qualify(name, package):
    if name and name.startswith('.'):
        return package + name
    if name and '.' not in name:
        return package + '.' + name
    return name


def parse_manifest(manifest_path, sdk=None):
    sdk = sdk or {'min_sdk': None, 'target_sdk': None}
    root = ET.parse(manifest_path).getroot()
    package = root.get('package')
    # uses-sdk may still be present in some decoded manifests.
    uses_sdk = root.find('uses-sdk')
    if uses_sdk is not None:
        for attr, field in (('minSdkVersion', 'min_sdk'), ('targetSdkVersion', 'target_sdk')):
            v = _a(uses_sdk, attr)
            if sdk.get(field) is None and v and v.isdigit():
                sdk[field] = int(v)

    permissions = [_a(p, 'name') for tag in ('uses-permission', 'uses-permission-sdk-23')
                   for p in root.findall(tag)]
    declared = [{'name': _a(p, 'name'), 'protectionLevel': _a(p, 'protectionLevel') or 'normal'}
                for p in root.findall('permission')]

    app = root.find('application')
    application = {}
    components = []
    if app is not None:
        for attr in ('permission', 'usesCleartextTraffic', 'networkSecurityConfig',
                     'debuggable', 'allowBackup'):
            application[attr] = _a(app, attr)
        app_perm = application['permission']
        for tag in COMPONENT_TAGS:
            for c in app.findall(tag):
                filters = _intent_filters(c)
                exported_attr = _a(c, 'exported')
                if exported_attr is None:
                    exported = _default_exported(tag, filters, sdk.get('target_sdk'))
                else:
                    exported = exported_attr == 'true'
                comp = {
                    'name': _qualify(_a(c, 'name'), package),
                    'type': tag,
                    'exported': exported,
                    'exported_attr': exported_attr,
                    'intent_filters': filters,
                    'permission': _a(c, 'permission') or app_perm,
                }
                if tag == 'provider':
                    comp['authorities'] = _a(c, 'authorities')
                    comp['read_permission'] = _a(c, 'readPermission')
                    comp['write_permission'] = _a(c, 'writePermission')
                    comp['grant_uri_permissions'] = _a(c, 'grantUriPermissions') == 'true'
                    comp['path_permissions'] = [
                        {k: _a(pp, k) for k in ('path', 'pathPrefix', 'pathPattern', 'permission',
                                                'readPermission', 'writePermission')}
                        for pp in c.findall('path-permission')]
                components.append(comp)

    return {
        'package': package,
        'permissions': permissions,
        'declared_permissions': declared,
        'components': components,
        'min_sdk': sdk.get('min_sdk'),
        'target_sdk': sdk.get('target_sdk'),
        'application': application,
    }


def decode(apk_path):
    """Decode `apk_path` into a temporary folder and return the manifest dict."""
    if not os.path.isfile(apk_path):
        raise ApkError('APK not found: %s' % apk_path)
    tmp = tempfile.mkdtemp(prefix='ate-')
    out_dir = os.path.join(tmp, 'decoded')
    try:
        run_apktool(os.path.abspath(apk_path), out_dir)
        manifest = os.path.join(out_dir, 'AndroidManifest.xml')
        if not os.path.exists(manifest):
            raise ApkError('apktool wrote no AndroidManifest.xml')
        return parse_manifest(manifest, _sdk_info(out_dir))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
