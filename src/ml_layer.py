"""ML layer: an APK-level logistic regression classifier on coarse app features.

Feature vector (FEATURES, one row per APK):
  exported_components    components with exported == True (apk.py applies the
                         Android default when android:exported is absent)
  permissions            <uses-permission> / <uses-permission-sdk-23> entries
  dangerous_permissions  of those, the ones in DANGEROUS_PERMISSIONS (Android
                         "dangerous" protection level, API 27 list)
  custom_permissions     <permission> elements the app declares
  internet_components    manifest components that can reach the network: only
                         counted when the app requests android.permission.INTERNET;
                         a component counts when its class, or one of its inner
                         classes (Outer$...), references a network API
                         (NETWORK_PATTERNS: java.net, javax.net.ssl, OkHttp,
                         HttpURLConnection, android.webkit.WebView). Without
                         INTERNET the value is 0.
  has_webview            app smali references android.webkit.WebView (0/1)
  has_sqlite             app smali references android.database.sqlite (0/1)
  has_crypto             app smali references javax.crypto or java.security (0/1)
  has_file_storage       app smali uses FileOutputStream, getExternalStorage*
                         or openFileOutput (0/1)
  has_sms                app smali references SmsManager (0/1)
Code features scan the smali* folders of the apktool output, skipping the
library prefixes code_analyzer.py skips (android/, androidx/, kotlin/,
com/google/), so support library code does not count.

Labels. data/ground-truth.csv lists every Ghera benchmark as a known
vulnerability: its Benign app exhibits the weakness, its Secure app is the
fixed version. The Benign APKs alone are a single class (all vulnerable), so
no classifier can be trained on them alone. The training set is therefore the
built Benign APKs with label 1 (vulnerable) plus the matching Secure APKs with
label 0 (not vulnerable), for the benchmarks that are in ground-truth.csv and
have a successful api27 build in data/build-results.csv (the set
tools/evaluate.py scores).

Model: StandardScaler + LogisticRegression(class_weight='balanced'). It is
evaluated with 5-fold StratifiedGroupKFold grouped by benchmark, so a
benchmark's Benign and Secure APKs are always in the same fold (otherwise the
model could memorise a pair across train and test). The decision threshold is
0.5 and no hyperparameters are tuned. Benign/Secure pairs usually differ by a
few lines of code, so most pairs have identical feature vectors; such a pair
always gets the same prediction, and one of its two APKs is then wrong. Expect
results near chance.

Usage:
  python src/ml_layer.py train [--refresh]
      Extract features (cached in data/ml-features.csv; --refresh re-decodes
      every APK), print cross-validated accuracy, precision and recall (mean
      and sd over folds, and pooled out-of-fold), write the out-of-fold
      predictions to data/ml-oof-predictions.csv (benchmark, variant, label,
      prob, pred), then fit on all data and save data/ml-model.pkl (a joblib
      dict with the pipeline and the feature names).
  python src/ml_layer.py combined [--eval CSV] [--oof CSV]
      APK-level "rules OR ML" scoring (see combined()).

API:
  features(apk_dict, decoded_dir=None) -> {feature: value}
  predict(apk_dict, decoded_dir=None, model_path=None) -> (pred 0/1, prob)
"""
import argparse
import csv
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))

DATA = os.path.join(ROOT, 'data')
BUILD_RESULTS = os.path.join(DATA, 'build-results.csv')
GROUND_TRUTH = os.path.join(DATA, 'ground-truth.csv')
EVAL_RESULTS = os.path.join(DATA, 'evaluation-results.csv')
FEATURES_CSV = os.path.join(DATA, 'ml-features.csv')
OOF_CSV = os.path.join(DATA, 'ml-oof-predictions.csv')
MODEL = os.path.join(DATA, 'ml-model.pkl')
APK_REL = os.path.join('app', 'build', 'outputs', 'apk', 'api27', 'debug', 'app-api27-debug.apk')
VARIANTS = (('Benign', 1), ('Secure', 0))
N_SPLITS = 5
SEED = 0

FEATURES = ['exported_components', 'permissions', 'dangerous_permissions', 'custom_permissions',
            'internet_components', 'has_webview', 'has_sqlite', 'has_crypto', 'has_file_storage',
            'has_sms']

LIBRARY_PREFIXES = ('android/', 'androidx/', 'kotlin/', 'com/google/')
INTERNET = 'android.permission.INTERNET'

# Permissions with protectionLevel "dangerous" (Android 8.1 / API 27).
DANGEROUS_PERMISSIONS = frozenset('android.permission.' + p for p in (
    'READ_CALENDAR', 'WRITE_CALENDAR', 'CAMERA', 'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS',
    'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'RECORD_AUDIO', 'READ_PHONE_STATE',
    'READ_PHONE_NUMBERS', 'CALL_PHONE', 'ANSWER_PHONE_CALLS', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
    'ADD_VOICEMAIL', 'USE_SIP', 'PROCESS_OUTGOING_CALLS', 'BODY_SENSORS', 'SEND_SMS', 'RECEIVE_SMS',
    'READ_SMS', 'RECEIVE_WAP_PUSH', 'RECEIVE_MMS', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'))
DANGEROUS_PERMISSIONS = DANGEROUS_PERMISSIONS | {'com.android.voicemail.permission.ADD_VOICEMAIL'}

NETWORK_PATTERNS = re.compile(r'Ljava/net/|Ljavax/net/ssl/|Lokhttp3/|Lcom/squareup/okhttp/|'
                              r'HttpURLConnection;|Landroid/webkit/WebView;')
CODE_PATTERNS = {
    'has_webview': re.compile(r'Landroid/webkit/WebView;'),
    'has_sqlite': re.compile(r'Landroid/database/sqlite/'),
    'has_crypto': re.compile(r'Ljavax/crypto/|Ljava/security/'),
    'has_file_storage': re.compile(r'Ljava/io/FileOutputStream;|->getExternalStorage\w*\(|'
                                   r'->openFileOutput\('),
    'has_sms': re.compile(r'Landroid/telephony/(gsm/)?SmsManager;'),
}


# ---------------------------------------------------------------- features

def app_classes(decoded_dir):
    """{dotted class name: smali text} for the app's own classes (library
    prefixes skipped). Empty when decoded_dir is None or missing."""
    classes = {}
    if not decoded_dir or not os.path.isdir(decoded_dir):
        return classes
    for entry in sorted(os.listdir(decoded_dir)):
        root = os.path.join(decoded_dir, entry)
        if not entry.startswith('smali') or not os.path.isdir(root):
            continue
        for dirpath, _, files in os.walk(root):
            for name in files:
                if not name.endswith('.smali'):
                    continue
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, root).replace(os.sep, '/')
                if rel.startswith(LIBRARY_PREFIXES):
                    continue
                with open(path, encoding='utf-8', errors='replace') as f:
                    classes[rel[:-len('.smali')].replace('/', '.')] = f.read()
    return classes


def _component_code(name, classes):
    """Smali text of the component class and its inner classes."""
    return [text for cls, text in classes.items() if cls == name or cls.startswith(name + '$')]


def features(apk_dict, decoded_dir=None):
    """Feature dict (keys FEATURES) for a manifest dict from apk.decode.
    decoded_dir defaults to apk_dict['decoded_dir']; without it the code
    features are 0."""
    decoded_dir = decoded_dir or apk_dict.get('decoded_dir')
    classes = app_classes(decoded_dir)
    perms = [p for p in apk_dict.get('permissions', []) if p]
    comps = apk_dict.get('components', [])
    internet = 0
    if INTERNET in perms:
        internet = sum(1 for c in comps
                       if any(NETWORK_PATTERNS.search(t) for t in _component_code(c['name'], classes)))
    out = {
        'exported_components': sum(1 for c in comps if c.get('exported')),
        'permissions': len(perms),
        'dangerous_permissions': sum(1 for p in perms if p in DANGEROUS_PERMISSIONS),
        'custom_permissions': len(apk_dict.get('declared_permissions', [])),
        'internet_components': internet,
    }
    for key, pattern in CODE_PATTERNS.items():
        out[key] = int(any(pattern.search(t) for t in classes.values()))
    return {k: out[k] for k in FEATURES}


def vector(feats):
    return [float(feats[k]) for k in FEATURES]


# ---------------------------------------------------------------- data set

def read_csv(path):
    with open(path, encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def benchmark_list():
    """(benchmark, category) with a successful api27 build that are in the ground truth."""
    categories = {r['folder']: r['category'] for r in read_csv(GROUND_TRUTH)}
    out, seen = [], set()
    for row in read_csv(BUILD_RESULTS):
        b = row['benchmark']
        if row['result'] == 'success' and 'api27' in row['flavor'] and b not in seen and b in categories:
            seen.add(b)
            out.append((b, categories[b]))
    return out


def apk_path(category, bench, variant):
    return os.path.join(ROOT, 'benchmarks', 'ghera', category, bench, variant, APK_REL)


def extract_apk(path):
    """Decode an APK into a temporary folder and return its feature dict."""
    import apk
    work = tempfile.mkdtemp(prefix='ate-ml-')
    try:
        manifest = apk.decode(path, work)
        return features(manifest)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def build_features(refresh=False, path=FEATURES_CSV, workers=4):
    """Rows {benchmark, category, variant, label, <features>} for every
    evaluated benchmark's Benign and Secure APK, cached in `path`. APKs not in
    the cache are decoded `workers` at a time (apktool runs as a subprocess)."""
    from concurrent.futures import ThreadPoolExecutor
    cache = {}
    if not refresh and os.path.exists(path):
        cache = {(r['benchmark'], r['variant']): r for r in read_csv(path)}
    todo = [(bench, category, variant, label) for bench, category in benchmark_list()
            for variant, label in VARIANTS]

    def one(item):
        bench, category, variant, label = item
        row = cache.get((bench, variant))
        if row is not None:
            return row
        p = apk_path(category, bench, variant)
        if not os.path.isfile(p):
            print('skip %s/%s: APK missing' % (bench, variant), file=sys.stderr)
            return None
        try:
            feats = extract_apk(p)
        except Exception as e:  # apktool failure: leave the APK out
            print('skip %s/%s: %s' % (bench, variant, e), file=sys.stderr)
            return None
        print('decoded %s/%s' % (bench, variant), file=sys.stderr, flush=True)
        return dict(benchmark=bench, category=category, variant=variant, label=label, **feats)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        found = list(pool.map(one, todo))
    rows = [{k: r[k] for k in ['benchmark', 'category', 'variant', 'label'] + FEATURES}
            for r in found if r is not None]
    with open(path, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['benchmark', 'category', 'variant', 'label'] + FEATURES)
        w.writeheader()
        w.writerows(rows)
    return rows


# ---------------------------------------------------------------- model

def make_model():
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    return make_pipeline(StandardScaler(), LogisticRegression(class_weight='balanced', max_iter=1000))


def cross_validate(rows, n_splits=N_SPLITS, seed=SEED):
    """5-fold StratifiedGroupKFold grouped by benchmark. Returns (per-fold
    metric dicts, out-of-fold rows {benchmark, variant, label, prob, pred})."""
    import numpy as np
    from sklearn.metrics import accuracy_score, precision_score, recall_score
    from sklearn.model_selection import StratifiedGroupKFold
    X = np.array([vector(r) for r in rows])
    y = np.array([int(r['label']) for r in rows])
    groups = np.array([r['benchmark'] for r in rows])
    prob = np.zeros(len(rows))
    folds = []
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    for train, test in cv.split(X, y, groups):
        model = make_model().fit(X[train], y[train])
        prob[test] = model.predict_proba(X[test])[:, 1]
        pred = (prob[test] >= 0.5).astype(int)
        folds.append({'accuracy': accuracy_score(y[test], pred),
                      'precision': precision_score(y[test], pred, zero_division=0),
                      'recall': recall_score(y[test], pred, zero_division=0)})
    oof = [{'benchmark': r['benchmark'], 'variant': r['variant'], 'label': int(r['label']),
            'prob': round(float(p), 4), 'pred': int(p >= 0.5)} for r, p in zip(rows, prob)]
    return folds, oof


def pooled(oof):
    tp = sum(1 for r in oof if r['pred'] and r['label'])
    fp = sum(1 for r in oof if r['pred'] and not r['label'])
    fn = sum(1 for r in oof if not r['pred'] and r['label'])
    correct = sum(1 for r in oof if r['pred'] == r['label'])
    return {'accuracy': correct / len(oof),
            'precision': tp / (tp + fp) if tp + fp else 0.0,
            'recall': tp / (tp + fn) if tp + fn else 0.0}


def train(refresh=False):
    import joblib
    import numpy as np
    import sklearn
    rows = build_features(refresh)
    pairs = {}
    for r in rows:
        pairs.setdefault(r['benchmark'], {})[r['variant']] = tuple(vector(r))
    complete = [p for p in pairs.values() if len(p) == 2]
    same = sum(1 for p in complete if p['Benign'] == p['Secure'])
    print('%d APKs (%d Benign = label 1, %d Secure = label 0), %d benchmarks; '
          '%d of %d Benign/Secure pairs have identical feature vectors'
          % (len(rows), sum(int(r['label']) for r in rows),
             sum(1 for r in rows if not int(r['label'])), len(pairs), same, len(complete)))
    folds, oof = cross_validate(rows)
    print('%d-fold StratifiedGroupKFold (grouped by benchmark), threshold 0.5:' % len(folds))
    for k in ('accuracy', 'precision', 'recall'):
        vals = np.array([f[k] for f in folds])
        print('  %-9s %.3f +/- %.3f  (folds: %s)' % (k, vals.mean(), vals.std(),
                                                     ', '.join('%.2f' % v for v in vals)))
    p = pooled(oof)
    print('pooled out-of-fold: accuracy %.3f, precision %.3f, recall %.3f'
          % (p['accuracy'], p['precision'], p['recall']))
    with open(OOF_CSV, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['benchmark', 'variant', 'label', 'prob', 'pred'])
        w.writeheader()
        w.writerows(oof)
    model = make_model().fit(np.array([vector(r) for r in rows]), np.array([int(r['label']) for r in rows]))
    joblib.dump({'model': model, 'features': FEATURES, 'sklearn_version': sklearn.__version__,
                 'n_train': len(rows)}, MODEL)
    coefs = model[-1].coef_[0]
    print('coefficients (standardised): ' + ', '.join('%s %+.2f' % (n, c) for n, c in zip(FEATURES, coefs)))
    print('wrote %s, %s, %s' % tuple(os.path.relpath(x, ROOT) for x in (FEATURES_CSV, OOF_CSV, MODEL)))
    return folds, oof


# ---------------------------------------------------------------- prediction

def load_model(model_path=None):
    import joblib
    bundle = joblib.load(model_path or MODEL)
    if list(bundle['features']) != FEATURES:
        raise ValueError('model features %s do not match %s' % (bundle['features'], FEATURES))
    return bundle


def predict(apk_dict, decoded_dir=None, model_path=None, bundle=None):
    """(pred, prob): pred 1 when the classifier calls the APK vulnerable
    (prob >= 0.5), prob the predicted probability of label 1."""
    bundle = bundle or load_model(model_path)
    prob = float(bundle['model'].predict_proba([vector(features(apk_dict, decoded_dir))])[0][1])
    return int(prob >= 0.5), prob


def finding(prob):
    """APK-level finding for a vulnerable prediction. It carries no CWE."""
    return {'component': '(application)', 'component_type': 'application',
            'issue': 'ml-vulnerable-app', 'cwe': 'ML',
            'confidence': 'medium' if prob >= 0.75 else 'low',
            'evidence': 'logistic regression on app-level features: P(vulnerable) = %.2f' % prob}


# ---------------------------------------------------------------- combined scoring

def combined(eval_csv=EVAL_RESULTS, oof_csv=OOF_CSV):
    """APK-level "rules OR ML" scores over the benchmarks in eval_csv.

    ML findings carry no CWE, so they cannot meet the CWE-matching rule of
    tools/evaluate.py. Per benchmark:
      TP = rules true_positive, or the ML out-of-fold prediction for the Benign APK is 1
      FP = rules false_positive, or the ML out-of-fold prediction for the Secure APK is 1
    Only out-of-fold predictions are used (each from a model that did not see
    that benchmark), never the model fit on all data. A benchmark without an
    ML prediction keeps its rule-only scores. Precision = TP / (TP + FP),
    recall = TP / benchmarks, as in tools/evaluate.py.
    Returns {'rules': {...}, 'ml': {...}, 'combined': {...}}."""
    oof = {(r['benchmark'], r['variant']): int(r['pred']) for r in read_csv(oof_csv)}
    rows = read_csv(eval_csv)
    tally = {k: {'tp': 0, 'fp': 0} for k in ('rules', 'ml', 'combined')}
    for r in rows:
        b = r['benchmark']
        rtp, rfp = int(r['true_positive'] or 0), int(r['false_positive'] or 0)
        mtp, mfp = oof.get((b, 'Benign'), 0), oof.get((b, 'Secure'), 0)
        for k, tp, fp in (('rules', rtp, rfp), ('ml', mtp, mfp), ('combined', rtp or mtp, rfp or mfp)):
            tally[k]['tp'] += tp
            tally[k]['fp'] += fp
    n = len(rows)
    for t in tally.values():
        t['n'] = n
        t['precision'] = t['tp'] / (t['tp'] + t['fp']) if t['tp'] + t['fp'] else 0.0
        t['recall'] = t['tp'] / n if n else 0.0
    return tally


def main(argv=None):
    p = argparse.ArgumentParser(prog='ml_layer', description=__doc__.split('\n')[0])
    sub = p.add_subparsers(dest='cmd', required=True)
    t = sub.add_parser('train', help='extract features, cross-validate, fit and save the model')
    t.add_argument('--refresh', action='store_true', help='ignore the feature cache')
    c = sub.add_parser('combined', help='rule-only vs rules OR ML (out-of-fold) scores')
    c.add_argument('--eval', default=EVAL_RESULTS, help='evaluation results CSV (tools/evaluate.py)')
    c.add_argument('--oof', default=OOF_CSV, help='out-of-fold predictions CSV')
    args = p.parse_args(argv)
    if args.cmd == 'train':
        train(args.refresh)
    else:
        res = combined(args.eval, args.oof)
        print('APK-level scoring over %d benchmarks (ML = out-of-fold predictions only)' % res['rules']['n'])
        for k, label in (('rules', 'rule-only'), ('ml', 'ML only'), ('combined', 'rules OR ML')):
            t = res[k]
            print('  %-12s TP %2d  FP %2d  precision %.2f  recall %.2f'
                  % (label, t['tp'], t['fp'], t['precision'], t['recall']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
