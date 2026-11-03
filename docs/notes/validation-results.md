# Independent validation on intentionally vulnerable apps

Run on 2026-11-02 with `python src/ate.py --apk <apk> --out data/validation-reports/` (static
analysis, default flags, no calibration) on three apps that publish their own vulnerability lists.
None of these apps was used to build or tune the rules.

| App | Version | APK source | Known list |
|-----|---------|------------|------------|
| BugBazaar | v1.2.1 | GitHub release, payatu/BugBazaar | [BugBazaar-known-vulnerabilities.md](../../data/validation-apks/BugBazaar-known-vulnerabilities.md) |
| InsecureShop | v1.0 | GitHub release, hax0rgb/InsecureShop | [InsecureShop-known-vulnerabilities.md](../../data/validation-apks/InsecureShop-known-vulnerabilities.md) |
| DIVA | beta (2016) | Payatu tarball via the Internet Archive (repo has no releases) | [diva-known-vulnerabilities.md](../../data/validation-apks/diva-known-vulnerabilities.md) |

Reports: [data/validation-reports/](../../data/validation-reports/). Per-finding labels:
[finding-labels.csv](../../data/validation-reports/finding-labels.csv). Per-vulnerability labels:
[known-labels.csv](../../data/validation-reports/known-labels.csv).

## Scoring rules

- **True positive (TP):** a known vulnerability for which at least one finding names the
  documented weakness (same weakness family, for example SQL injection, WebView settings,
  exported component, implicit intent) on the component where the vulnerability lives. App-level
  items (task hijacking) match app-level findings.
- **False negative (FN):** a known vulnerability with no such finding. This includes
  vulnerabilities whose component was flagged only for something else ("located only", for
  example the exported deep-link activity was reported but its weak URL check was not).
- **False positive (FP):** a finding that matches no known vulnerability. Findings that only
  locate a known vulnerability (its entry point) are not counted as FP.
- Several findings can support one TP; duplicates are neither TP nor FP. Precision is
  TP / (TP + FP) and recall is TP / (TP + FN), both counted in known vulnerabilities.
- The known lists are the README lists, counted as written. BugBazaar's "APP Protection"
  section (root, Magisk, emulator and Frida detection) lists protections, not vulnerabilities,
  and is left out. The mapping from README wording to a weakness type is ours, and the
  component placement was checked against each app's public source.

## Results

| App | Known Vulnerabilities | Tool Findings | True Positives | False Positives | False Negatives | Precision | Recall |
|-----|----------------------:|--------------:|---------------:|----------------:|----------------:|----------:|-------:|
| BugBazaar | 42 | 44 | 13 | 16 | 29 | 0.45 | 0.31 |
| InsecureShop | 19 | 29 | 8 | 6 | 11 | 0.57 | 0.42 |
| DIVA | 13 | 11 | 5 | 2 | 8 | 0.71 | 0.38 |
| **Overall** | **74** | **84** | **26** | **24** | **48** | **0.52** | **0.35** |

Two other views of the same labels:

| View | BugBazaar P / R | InsecureShop P / R | DIVA P / R | Overall P / R |
|------|-----------------|--------------------|------------|---------------|
| Lenient (a located-only vulnerability counts as found) | 0.54 / 0.45 | 0.68 / 0.68 | 0.78 / 0.54 | 0.62 / 0.53 |
| Finding level (share of findings tied to a known vulnerability) | 0.64 | 0.79 | 0.82 | 0.71 |

Finding-level precision counts both matching and locating findings (BugBazaar 28 of 44,
InsecureShop 23 of 29, DIVA 9 of 11, overall 60 of 84).

### Where the false positives come from

18 of the 24 false positives are in bundled third-party libraries (Razorpay, Glide, Evernote
android-job, Picasso, and the uploadservice library in InsecureShop beyond its documented
exported service). The other 6 are true of the app but not in its list: cleartext HTTP allowed
(BugBazaar, DIVA), default task affinity (InsecureShop, DIVA), missing certificate pinning
(InsecureShop) and an Android ID read (BugBazaar). Without library findings, overall precision
would be 26 / 32 = 0.81.

### Per-app notes

- **BugBazaar:** found exported components, the insecure broadcast receiver and the protected
  component launch through it, the exported SMS service (also as a taint flow from an intent
  extra to `sendTextMessage`), fragment injection, both SQL injections, the insecure content
  provider, the mutable PendingIntent, dynamic code loading, WebView JavaScript interface and
  file-access flags, and task hijacking. Missed: debuggable and backup flags (both set in the
  manifest), logging of credentials, hardcoded secrets, plaintext storage, the typo permission
  on the contacts provider, URL and host checks in WebViews and deep links, clipboard, tapjacking,
  and the items that need a server or runtime view (Firestore rules, file upload, passcode and
  Frida bypass, CSRF, XSS).
- **InsecureShop:** found the file theft through ChooserActivity, the insecure broadcast receiver,
  the implicit broadcast with credentials, the implicit-intent URL chain, the content provider with
  a normal-level permission, the exported upload service of the vulnerable library,
  `onReceivedSslError` calling `proceed()`, and the WebView settings. Missed: hardcoded and stored
  credentials, logging, code execution through `createPackageContext`, the FileProvider root path,
  the AWS Cognito setup, and the URL, host, intent-redirection and `setResult` flaws, whose
  activities were flagged only as exported.
- **DIVA:** found the three access-control challenges, the SQL injection, and the external storage
  write. Missed: logging, hardcoded keys (Java and native), SharedPreferences, SQLite and temp-file
  storage, and the native buffer overflow. The WebView URL challenge and the SQLite storage
  challenge were located (JavaScript enabled, raw `execSQL`) but not named.

## Comparison with the Ghera benchmark

| Dataset | Scope | Precision | Recall |
|---------|-------|----------:|-------:|
| Ghera (53 benchmarks, standard mode) | one planted weakness per app, Benign and Secure pair | 0.79 | 0.98 |
| BugBazaar | 42 documented vulnerabilities | 0.45 | 0.31 |
| InsecureShop | 19 documented vulnerabilities | 0.57 | 0.42 |
| DIVA | 13 documented vulnerabilities | 0.71 | 0.38 |
| Validation overall | 74 documented vulnerabilities | 0.52 | 0.35 |

The two sets of numbers are not measured the same way. On Ghera a false positive is a finding
with the benchmark's own CWE on the Secure APK, and each app has one known weakness that the
rules were written for. Here every finding that is not in the README list is a false positive,
the apps bundle third-party libraries, and the lists include server-side and runtime items a
static APK scan cannot see. Even so, the gap is large and shows where the rules do and do not
generalize.

### By vulnerability type

The 74 known vulnerabilities grouped by type, next to the closest Ghera category:

| Type | Known | Found (TP) | Validation recall | Closest Ghera category (recall) |
|------|------:|-----------:|------------------:|--------------------------------|
| Exported components and inter-app communication | 21 | 15 | 0.71 | ICC (0.94) |
| SQL injection and code loading | 6 | 4 | 0.67 | Storage, SQL injection benchmarks (1.00) |
| Vulnerable library component | 1 | 1 | 1.00 | none |
| WebView (settings, URL and host checks, file theft) | 16 | 4 | 0.25 | Web (1.00) |
| Storage and data leakage (logs, prefs, DB, clipboard, cache) | 15 | 2 | 0.13 | Storage, external storage benchmarks (1.00) |
| Hardcoded credentials and keys | 4 | 0 | 0.00 | none |
| Manifest flags and UI (debuggable, backup, tapjacking) | 3 | 0 | 0.00 | System (1.00) |
| Server-side, runtime or app logic | 8 | 0 | 0.00 | none (out of static scope) |
| **Total** | **74** | **26** | **0.35** | **0.98** |

Leaving out the 8 server-side, runtime and logic items (Firestore rules, AWS Cognito, file
upload, passcode and Frida bypass, runtime code modification, improper input validation,
exception handling), recall is 26 / 66 = 0.39.

### Caught well in both datasets

- **Exported components and IPC.** Exported activities, services, receivers and providers
  without permission, weak (normal-level) provider permissions, receivers that start activities
  from untrusted intents, implicit broadcasts, mutable PendingIntents and fragment injection.
  This is the strongest area on Ghera (ICC recall 0.94) and here (0.71).
- **SQL injection** through `rawQuery` and `execSQL` with built strings (BugBazaar x2, DIVA).
- **Dynamic code loading** with `DexClassLoader` (BugBazaar).
- **WebView settings**: JavaScript, file access and universal file URL access, and
  `onReceivedSslError` calling `proceed()`.
- **External storage writes** (DIVA part 4).

### Missed consistently

- **Logic inside WebView and deep-link handlers.** The tool flags the exported deep-link
  activity and its WebView settings but not the weak URL or host check (`contains`, `endsWith`,
  path switch), open redirects, or intent redirection through an `extra_intent` or `setResult`.
  Ghera's Web benchmarks test WebView settings and WebViewClient callbacks that accept every
  URL, not checks done in an activity before `loadUrl`, so Web recall there (1.00) does not carry over.
- **Sensitive data in logs, SharedPreferences, SQLite and temp files.** Ghera's Storage
  benchmarks test external storage, directory traversal and SQL injection, which are caught;
  plain credential storage in private files, which these apps document, has no rule.
- **Hardcoded credentials and keys**, in Java and in native libraries.
- **Manifest flags** `android:debuggable` and `android:allowBackup`, and tapjacking. BugBazaar
  sets both flags; the manifest parser reads them but no rule reports them.
- **FileProvider path configuration** (root path in `provider_paths.xml`) and the
  `createPackageContext` code execution pattern.
- **Native code** (DIVA buffer overflow, native hardcoded key): the tool reads smali only.

### Precision

On Ghera, 14 false positives remain, mostly findings that are true of the Secure app. Here
18 of 24 false positives are in third-party library code, which Ghera apps do not contain.
Excluding library packages, or reporting them in a separate section, would raise validation
precision from 0.52 to 0.81, close to the Ghera figure.
