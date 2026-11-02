# Threat Models, Ground Truth and a Layered Analyzer for the Ghera Android Vulnerability Benchmarks

Short paper draft, structured for submission to PROMISE or Empirical Software Engineering.

## Abstract

Ghera is a repository of Android app vulnerability benchmarks in which each benchmark pairs a vulnerable Benign app with a Malicious app that exploits it and a Secure app that fixes it. Such benchmarks are useful as ground truth only if every vulnerability and every fix is documented precisely and still behaves as described on current Android versions. We report on four artifacts built on Ghera (tag `Jan2019`, 57 benchmarks in eight categories): 24 code-referenced threat models for the ICC and Web benchmarks, with standards mappings for 31 more; a ground truth dataset mapped to CWE, OWASP MASVS v2, MASWE and MASTG; a drift matrix design covering seven Android API levels; and a four-layer analyzer combining manifest rules, smali code patterns, interprocedural taint analysis and dynamic testing over adb. On the 53 benchmarks with an API 27 build, the static layers reach precision 0.53 and recall 0.77 when reviewed secondary CWEs count, and precision 0.52 and recall 0.74 under a strict CWE match. Reading the benchmarks produced 234 logged issues and two confirmed Secure app bugs in which a permission name mismatch makes the fix work only by accident.

## 1 Introduction

**Ghera.** Ghera (Mitra and Ranganath, PROMISE 2017) captures known Android app vulnerabilities as small sets of apps: a Benign app with the vulnerability, a Malicious app that exploits it, and a Secure app that removes it. Most benchmarks also ship a Testing project with UI Automator instrumentation tests that check the exploit result against Benign and Secure. Benchmarks are Lean (only the code needed to show the vulnerability) or Fat (the vulnerability inside a larger app). Tag `Jan2019` (commit `6289f39d`) holds 57 benchmarks: Crypto 5, ICC 18, Networking 8, NonAPI 2, Permission 2, Storage 7, System 7 and Web 8. The READMEs state testing on Android 4.4 to 8.1 (API 19 to 27).

**Rekha.** Rekha is the evaluation repository of Ranganath and Mitra, "Are free Android app security analysis tools effective in detecting known vulnerabilities?" (Empirical Software Engineering, 2019; preprint 2018). The study ran free Android security analysis tools against Ghera and found that they detected only part of the known vulnerabilities. That result rests on Ghera being correct ground truth: each Benign app must show its vulnerability, each Secure app must fix it, and both must do so on the platform the tools target.

**Motivation.** Three gaps motivate this work. The READMEs describe each vulnerability in prose, and the link from that prose to the code, to a weakness taxonomy and to a test is informal. Android has changed since API 27 (implicit broadcast limits, export rules for components with intent filters, pending intent mutability, background activity start limits), which may change whether an exploit still works. And a new analyzer needs a ground truth that states which CWE a correct detection should name.

**Contributions.** (1) A threat model library in which every statement points to a file and line, with a verified standards reference. (2) A ground truth dataset with a documented schema. (3) A drift matrix and harness design that separates device API level from target SDK. (4) A four-layer analyzer and an evaluator, including two-app dynamic testing and automated README replay. (5) A log of 234 benchmark issues and two confirmed Secure app bugs.

## 2 Methodology

### 2.1 Threat model library

Each threat model follows a fixed template with ten sections after a benchmark header: system description, assets and attacker model, STRIDE, LINDDUN, attack tree, standards mapping, evidence, mitigation, and open questions, plus two Mermaid diagrams rendered to SVG. Every claim about an app points to a file and line in the benchmark. The library has 24 full models (16 ICC, 8 Web). The 31 benchmarks in the other six categories are mapped to standards without a full model, and two benchmarks are not yet drafted (`UnprotectedBroadcastRecv-PrivEscalation-Fat` and `WeakChecksOnDynamicInvocation-DataInjection-Lean`). Every CWE, OWASP MASVS v2, MASWE and MASTG ID was checked against its official page and recorded with its exact title in a standards reference, where DISCOURAGED CWEs are marked. A lint script checks IDs and titles, template headings, links and Mermaid syntax.

The ground truth dataset (`data/ground-truth.csv`, 57 rows) records per benchmark the README's Android range, the expected Benign and Secure results with a source reference, the standards IDs, a link to the model and an evidence status. Values come only from the threat models and mappings, the README and the Testing code; a blank cell means "not stated in the sources". A `secondary_cwe_ids` column supports scoring (Section 2.3).

### 2.2 Tool architecture

The analyzer (`src/ate.py`) decodes an APK with apktool and runs four layers. Each finding carries a component, an issue, a CWE ID, a confidence (high, medium or low) and, for code findings, the smali file, line and triggering instruction.

- **Layer 1, manifest attack surface (`surface.py`).** Exported components without a permission, components exported only through an intent filter, cleartext HTTP (local-only cleartext in the network security config is skipped), providers whose access depends on caller-supplied paths, and task affinity hijacking (a `taskAffinity` naming another package, or `singleTask` and `singleInstance` launch modes). Merged findings keep one entry per component and CWE.
- **Layer 2, smali code patterns (`code_analyzer.py`).** Each method is read top to bottom with a simple register model; branches are not followed, so the layer is heuristic, and library packages are skipped. Patterns cover cryptography misuse, permissive TLS validation, WebView settings, SQL concatenation, directory traversal, clipboard use, dynamic code loading, broadcast and pending intent misuse, and device identifiers.
- **Layer 3, interprocedural taint (`taint_analyzer.py`, `call_graph.py`).** A call graph is built from the app's invoke instructions. Taint flows from intent extras, bundles, provider cursors and text fields into arguments and back through return values, up to a fixed depth, with confidence one step lower per call level. Null checks, `equals` comparisons and try blocks stop a flow.
- **Layer 4, dynamic testing over adb (`dynamic_analyzer.py`).** The APK is installed and started on an emulator; every exported receiver gets an explicit shell broadcast, receivers registered at run time are found through `dumpsys` and probed, and internal files, the task stack and logcat are compared around each probe.

A two-app mode installs the Benign app with the benchmark's Malicious app and reports task hijacks, foreign activities in the benign task, storage changes and permission denials. A README runner (`tools/readme_runner.py`) parses a README's numbered exploit steps and replays them as install, launch, tap, back and adb actions, capturing logcat and the foreground activity after each step.

**Changes in this round.**

- *P1-1, certificate pinning.* `certificate_pinning_missing` (CWE-295) fires when the network security config has no pin set, or when there is no config and cleartext is not disabled. It is gated on the app's own code opening network or TLS connections and skipped when the code pins certificates itself (okhttp `CertificatePinner`, or a custom `KeyStore` passed to a `TrustManagerFactory`).
- *P1-2, fragment injection.* `fragment_injection` (CWE-470) reports `PreferenceActivity` subclasses without `isValidFragment` or with one that always returns true, and `Class.forName` or `Fragment.instantiate` calls in classes that read an intent extra without validating the fragment name.
- *P2-1, class hierarchy taint.* Tainted arguments to virtual or interface calls on app classes are followed into overrides up to two levels below the owner class.
- *P2-2, inter-component taint.* When an intent with tainted extras reaches `startActivity`, `startService` or `sendBroadcast`, the target is resolved from an explicit class or matching intent filters (including code-registered receivers) and its entry methods are scanned with extra reads as sources.
- *P2-3, WebView JavaScript interfaces.* Methods of objects passed to `addJavascriptInterface` that access files, the network, databases or send intents are reported.
- *P2-4, sticky broadcast receivers.* Receivers registered for a sticky broadcast the app sends, and acting on its data without a check, are reported.
- *P2-5, provider path permissions.* Exported providers protected only by `path-permission` entries, or by exact `android:path` matches that leave subpaths open, are reported as CWE-284 candidates; because CWE-284 is DISCOURAGED, each finding notes that more specific children are to be reviewed.

### 2.3 Evaluation design

**Sample.** The evaluator (`tools/evaluate.py`) scores every benchmark with a successful `api27` build: 53 benchmarks across all eight categories. The Secure APK of `MergeManifest-UnintendedBehavior-Lean` was not built and is scored with zero Secure findings.

**Scoring.** A true positive (TP) means the Benign APK has a finding whose CWE matches a ground-truth CWE. A false positive (FP) means the Secure APK has any finding. Precision is TP / (TP + FP); recall is TP divided by the benchmarks evaluated, since each Benign app has one known vulnerability. A CWE matches directly, through a small one-step mapping of related CWEs, or through the `secondary_cwe_ids` column. The strict score (direct matches with `cwe_ids` only) is always reported alongside.

**P1-3, ground truth correction.** Candidate secondary CWEs were reviewed against each threat model and README. Two were accepted because the finding CWE is the parent of the ground-truth CWE and names the benchmark's own weakness: CWE-200 for `ClipboardUse-InformationExposure-Lean` (ground truth CWE-359) and CWE-829 for `WebViewAllowFileAccess-UnauthorizedFileAccess-Lean` (ground truth CWE-830). Ten candidates were rejected as incidental findings rather than the benchmark's weakness.

**P1-4, two-app scoring.** With a device attached, each benchmark with a built Malicious APK (41 benchmarks) runs twice in two-app mode. Benign plus Malicious findings are added to Benign; Secure plus Malicious findings are added to Secure, so a two-app finding that also appears against the fixed app counts as a false positive and precision stays honest.

**P1-5, README runner scoring.** README steps exercise the Benign app only; observations from steps that act on Secure, and from all later steps, are ignored because Benign and Secure share a package name. README findings can add true positives but never false positives, so this score is reported separately.

**Rescoring.** A rescore mode scores the reports saved by a previous run against the current ground truth without re-running the analyzer, which isolates ground truth changes from detection changes.

## 3 Results

### 3.1 Precision and recall

The table gives the final static evaluation (`python tools/evaluate.py --no-dynamic`) after all rules of this round, next to the run before it.

| Configuration | TP | FP | Precision | Recall | Benchmarks |
|---------------|---:|---:|----------:|-------:|-----------:|
| Before this round, static (strict CWE and with mapping) | 37 | 35 | 0.51 | 0.70 | 53 |
| Static, strict CWE (`cwe_ids` only) | 39 | 36 | 0.52 | 0.74 | 53 |
| Static, with secondary CWEs | 41 | 36 | 0.53 | 0.77 | 53 |

By category (static, with secondary CWEs): Crypto 4 of 5 (precision 0.50), ICC 11 of 16 (0.50), Networking 7 of 8 (0.47), NonAPI 1 of 1 (1.00), Permission 1 of 2 (0.50), Storage 5 of 7 (0.56), System 6 of 6 (1.00), Web 6 of 8 (0.43).

The round adds four true positives and one false positive. Two come from new rules and count under the strict match: `fragment_injection` reports the Benign app of `FragmentInjection-PrivEscalation-Lean` under CWE-470, and `certificate_pinning_missing` reports the Benign app of `UnpinnedCertificates-MITM-Lean` under CWE-295; neither fires on the corresponding Secure app. The other two come from the reviewed ground truth correction (P1-3): `ClipboardUse-InformationExposure-Lean` (CWE-200) and `WebViewAllowFileAccess-UnauthorizedFileAccess-Lean` (CWE-829). The new false positive is the Secure app of `UnEncryptedSocketComm-MITM-Lean`, which opens a network connection without pinning and is now flagged by `certificate_pinning_missing`. The other Secure apps that rule fires on already had findings, so the false positive count rises by one only.

The dynamic layer, two-app scoring (P1-4) and README runner scoring (P1-5) are implemented and were checked live on single benchmarks (on `TaskAffinity-ActivityHijack-Lean` the Benign plus Malicious run reports a task hijack under CWE-1021 and the Secure plus Malicious run reports nothing), but the full emulator evaluation of this round did not complete: it was stopped for low system memory after 2 of 53 benchmarks. Dynamic, two-app and README runner scores are therefore not reported for this round. In the previous full dynamic run the dynamic layer reported 56 findings across 11 benchmarks and changed no score.

Inter-component taint resolved 12 cross-component edges in 6 benchmarks but found no new sinks on the Ghera set. The WebView JavaScript interface and sticky broadcast receiver rules produced no new findings on Ghera. The provider path-permission rule fires on the Benign app of `InadequatePathPermission-InformationExposure-Lean` and not on its Secure app, as intended; that benchmark was already a true positive through CWE-926.

**Misses.** Before this round 16 benchmarks had no true positive; after it 12 have none. Most need rules that do not exist yet (external storage writes, WebView SSL error handlers, open server sockets, the default task affinity, intent filter priority on activities, uncaught exceptions); in others the rules fire under a CWE that neither the ground truth nor the mapping lists. `WeakChecksOnDynamicInvocation-DataInjection-Lean` has no ground-truth CWE and cannot score.

**Why precision stays near 0.5.** A Secure APK is a false positive when it has any finding. Many Secure apps still export components or keep code the rules report, even where the specific weakness is fixed, and several leave the underlying weakness in place (Section 3.3). The rule is deliberately conservative: it gives no credit for separating the fixed weakness from residual findings.

### 3.2 Drift matrix findings

The drift matrix (`data/drift-matrix.csv`) plans one row per benchmark and API level for API 22, 25, 27, 28, 30, 33 and 34: 57 benchmarks times 7 levels, 399 rows. Each row records the device API level, the target SDK the installed APK actually declares, whether the exploit worked on Benign and was blocked on Secure, notes and a screenshot. The design separates two axes: running the same APK on newer devices measures platform changes that apply to every app, while rebuilding with a raised target SDK measures changes that apply only to apps targeting the new SDK.

Only the API 27 system image is installed, and the emulator run of this round did not complete, so this round measured the static layers on API 27 only. The drift study script (`tools/drift_study.py`) analyzes every Benign API 27 APK, counts static findings once (the static layers do not depend on the device), runs the dynamic layer on one emulator per installed level, and writes per-level counts and the dynamic findings gained or lost against API 27 to `data/drift-matrix-results.csv`. In its static-only mode it wrote 53 API 27 rows with blank dynamic columns, and `data/drift-static-patterns.csv` lists the patterns each Benign app fires. The most common are `exported-no-permission` (21 Benign apps), `cleartext-http` (16), `implicit-intent`, `certificate_pinning_missing` and `js_enabled` (7 each) and `taint-flow` (6). The last full dynamic baseline on API 27 (previous round) was 47 receivers accepting external broadcasts (CWE-926), 7 task hijacks (CWE-1021), 1 deleted file (CWE-922) and 1 observed permission denial.

The cross-level study would measure whether each exploit still works on Benign and is still blocked on Secure under later platform changes (API 26 implicit broadcast limits, API 29 and 30 background activity start limits, API 31 export and pending intent mutability rules), and which dynamic findings appear or disappear relative to API 27. It would also expose limits of the benchmark tests: every Testing class carries `@SdkSuppress(maxSdkVersion = 27)` or lower, so on API 28 and later the runner reports zero tests, which must be recorded as inconclusive rather than a pass. The build toolchain (Android Gradle plugin 3.1.2, build tools 27.0.3, JDK 8) cannot target current SDKs without porting.

### 3.3 Secure app bugs

Writing the threat models produced 234 logged benchmark issues, each with a file, line and evidence status. Most are differences between README and code (wrong names, missing steps, attacks the code does not carry out). Others concern Secure apps whose fix looks incomplete: weaker protection than needed, exposure left in place, fixes that break the app (a random IV or salt that is never stored), and Secure tests that pass either way (one is `assert true;`).

A scan of all 55 Secure manifests for declared and required permission names confirmed two bugs from source:

1. In `UnprotectedBroadcastRecv-PrivEscalation-Lean`, Secure declares the signature permission `edu.ksu.cs.benign.permission1`, but its exported SMS-sending receiver requires `edu.ksu.cs.secure.permission1`.
2. In `IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean`, Secure declares the signature permission `edu.ksu.cs.benign.perm`, but `SensitiveActivity`, which returns sensitive information to its caller, requires `edu.ksu.cs.secure.perm`.

No app in either benchmark defines the required name, so the declared signature permission protects nothing. Malicious is blocked only because it lacks a permission nobody defines; any installed app can define that name with a normal protection level, request it and pass the check. Both fixes therefore work by accident, not by design. The Secure tests check only that the exploit result is absent, so they pass with or without the mismatch. Each fix is a one-line manifest change, and a test checking the declared permission's protection level against the component's required permission would catch the mismatch. Neither bug was verified on a device.

## 4 Discussion

### 4.1 Comparison to Rekha 2018

Rekha and this work both measure detection of the known vulnerabilities in Ghera, but the comparison is directional only. Rekha ran several free third-party tools; this work evaluates one analyzer developed with the benchmarks in view. Rekha used an earlier version of Ghera; this work uses tag `Jan2019` and scores 53 of its 57 benchmarks. Rekha used its own definition of a detection; this work requires a CWE match against a ground truth derived from the threat models and counts any Secure finding as a false positive. The numbers in Section 3.1 should therefore not be read as an improvement over the tools Rekha evaluated. In both, a substantial share of known vulnerabilities goes undetected; here the misses point to specific missing rules.

### 4.2 Limitations

*Construct validity.* The ground truth comes from READMEs, Testing code and threat models, none observed on a device beyond a smoke test and the API 27 runs. The secondary CWE review is a judgment, hence the strict score. The FP definition counts residual Secure findings that may be real weaknesses (Section 3.3).

*Internal validity.* The analyzer was built with Ghera in view, so its Ghera recall overstates recall on unseen apps. The code and taint layers do not follow branches and can both miss and invent flows. Dynamic probes use shell broadcasts and launcher starts, which do not reproduce every exploit.

*External validity.* Lean benchmarks are small apps with one vulnerability each; results do not transfer directly to large apps with libraries, obfuscation and native code.

*Reliability.* Only API 27 was measured, and the full dynamic, two-app and README runner evaluation of this round was stopped for low system memory, so this round's scores cover the static layers only. The Fat benchmark and one Secure APK were not built. The two Secure app bugs were established by reading source, not by running an exploit.

### 4.3 Future work

1. Run the drift study on API 22, 25, 28, 30, 33 and 34 once the system images are installed, then the target SDK axis on a ported copy outside the Ghera checkout.
2. Add rules for the remaining misses listed in Section 3.1.
3. Score Secure findings that match the ground-truth CWE separately from residual findings.
4. Report the Secure app bugs and the issue log to the Ghera maintainers, and verify each "read in code, not yet run" issue on a device.
5. Add benchmarks for gaps Ghera does not cover. Three candidates from BenchPress are `WebView.loadUrl` with extra headers, `Os.open` with a world-accessible mode, and `KeyGenParameterSpec` with `setAttestationChallenge(null)`.
6. Draft the two missing threat models and extend full models to the other six categories.

## 5 Conclusion

Ghera remains a useful vulnerability benchmark, but using it as ground truth needs more structure than its READMEs provide. Code-referenced threat models, a ground truth dataset with verified standards IDs and a drift design that separates device level from target SDK make that structure explicit. A four-layer analyzer scored against this ground truth reaches moderate recall, with precision held near 0.5 by a deliberately strict false positive rule. Building the models exposed 234 benchmark issues and two Secure apps whose permission protection works only by accident, which shows that benchmark fixes need tests that check the intended protection, not only the absence of one exploit.

## References

1. J. Mitra and V.-P. Ranganath. "Ghera: A Repository of Android App Vulnerability Benchmarks." Proceedings of the 13th International Conference on Predictive Models and Data Analytics in Software Engineering (PROMISE), 2017.
2. V.-P. Ranganath and J. Mitra. "Are free Android app security analysis tools effective in detecting known vulnerabilities?" Empirical Software Engineering, 2019. Preprint 2018.
3. MITRE. Common Weakness Enumeration (CWE). https://cwe.mitre.org/
4. OWASP. Mobile Application Security Verification Standard (MASVS), version 2. https://mas.owasp.org/MASVS/
5. OWASP. Mobile Application Security Weakness Enumeration (MASWE). https://mas.owasp.org/MASWE/
6. OWASP. Mobile Application Security Testing Guide (MASTG). https://mas.owasp.org/MASTG/
