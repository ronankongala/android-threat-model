# Project summary: android-threat-engine

Prepared for Professor Joydeep Mitra. Status as of 2026-11-01.

## Ghera and Rekha

**Ghera** (Mitra and Ranganath, PROMISE 2017) is a repository of Android app vulnerability benchmarks. Each benchmark captures one known vulnerability as a small set of apps: a **Benign** app that has the vulnerability, a **Malicious** app that exploits it, and a **Secure** app that fixes it. Most benchmarks also include a **Testing** project with UI Automator instrumentation tests that check the exploit result against Benign and Secure. Benchmarks are "Lean" (only the code needed to show the vulnerability) or "Fat" (the vulnerability inside a larger app). This project uses the tag `Jan2019` (commit `6289f39d`), which holds 57 benchmarks in eight categories: Crypto 5, ICC 18, Networking 8, NonAPI 2, Permission 2, Storage 7, System 7 and Web 8.

**Rekha** is the evaluation repository for Ranganath and Mitra, "Are free Android app security analysis tools effective in detecting known vulnerabilities?" (Empirical Software Engineering, 2019). The study ran free Android security analysis tools against the Ghera benchmarks and found that the tools detected only part of the known vulnerabilities. Rekha is the main reason Ghera matters for this project: the benchmarks are only useful as ground truth if each one shows its vulnerability, and its fix, on the Android versions in use.

## What this project adds

1. **Threat model library** (`docs/threat-models/`). A fixed template with ten sections (system description, assets and attacker model, STRIDE, LINDDUN, attack tree, standards mapping, evidence, mitigation and open questions, after a benchmark header) and two Mermaid diagrams per model. Every statement about an app points to a file and line in the benchmark. Every standards ID (CWE, OWASP MASVS v2, MASWE and MASTG) was checked against the official page and recorded with its exact title in `standards-reference.md`. Status: 24 full models (16 ICC, 8 Web), 31 benchmarks in the other categories mapped to standards without a full model (`other-categories-mapping.md`), and 2 not yet drafted (`UnprotectedBroadcastRecv-PrivEscalation-Fat` and `WeakChecksOnDynamicInvocation-DataInjection-Lean`). A docs lint script (`tools/lint_docs.py`) checks IDs, titles, headings, links and diagrams. The 50 diagrams are rendered to SVG in `docs/diagrams/`.
2. **Ground truth dataset** (`data/ground-truth.csv`, schema in `data/ground-truth.schema.md`). One row per benchmark with the README's Android range, the expected Benign and Secure results, the standards IDs and the evidence status, all taken from the README, the Testing code or the threat models.
3. **Drift matrix** (`data/drift-matrix.csv`). One row per benchmark and API level (22, 25, 27, 28, 30, 33 and 34; 399 rows) to record whether the exploit still works on Benign and is still blocked on Secure on newer Android versions. The design (`docs/notes/drift-harness-design.md`) separates two axes: the device API level and the target SDK the app is rebuilt with, since many platform changes apply only to apps that target a new SDK.
4. **Tool**. Build and emulator scripts are in place (`tools/build_all.ps1`, `tools/create_avds.ps1`, `env.ps1`, and a manual run template). The analysis tool itself has not been started; `src/` is empty.
5. **Evaluation**. Planned in two parts: the drift study, and then running the tool (and, if time allows, current versions of the Rekha tools) against the ground truth. Not started beyond one smoke test.

## Key findings so far

All findings below come from reading the benchmark code. Except for the smoke test, nothing has been run yet, so each is marked "Read in code, not yet run" in `docs/notes/benchmark-issues.md`, which lists 234 issues in 56 benchmarks.

**Smoke test.** `DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean` was built (Gradle 4.4, JDK 8, flavor `api27`) and run on an API 27 emulator. The exploit worked against Benign and had no effect against Secure, as the README says. The build and run toolchain therefore works.

**Secure apps whose fix looks incomplete.** In several benchmarks the Secure app removes the specific exploit path but leaves the underlying weakness, or the Secure test cannot tell a fixed app from a broken one:

- *Permission names that do not match.* In `UnprotectedBroadcastRecv-PrivEscalation-Lean` and `IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean`, Secure declares a signature permission named `edu.ksu.cs.benign...` but its component requires `edu.ksu.cs.secure...`, which no app declares. The exploit is blocked, but so is every legitimate caller, possibly including Secure itself.
- *Weaker protection than needed.* `DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean` Secure uses a `dangerous` permission, which any app can request; `FragmentInjection-PrivEscalation-Lean` Secure blocks one fragment name with a deny-list.
- *Exposure left in place.* `EmptyPendingIntent-PrivEscalation-Lean` and `StickyBroadcast-DataInjection-Lean` Secure still send implicit broadcasts with no permission; `InadequatePathPermission-InformationExposure-Lean` Secure keeps an exported activity that grants read access to any caller-chosen path; `WebViewInterceptRequest-MITM-Lean` Secure still exposes the JavaScript bridge; `InsecureSSLSocket-MITM-Lean` Secure keeps the trust-all TrustManager; `CheckValidity-InformationExposure-Lean` Secure accepts any non-expired certificate and keeps an always-true HostnameVerifier.
- *Fixes that break the app.* `BlockCipher-NonRandomIV-InformationExposure-Lean` and `PBE-ConstantSalt-InformationExposure-Lean` Secure use a random IV or salt but do not store it, so the app cannot decrypt its own data.
- *Secure tests that pass either way.* `MergeManifest-UnintendedBehavior-Lean` Secure is `assert true;`; `BlockCipher-ECB-InformationExposure-Lean` Secure looks for a view in the wrong package; `UnEncryptedSocketComm-MITM-Lean` Secure passes because the app has no INTERNET permission, not because of TLS; `UniqueIDs-IdentityLeak-Lean` Secure makes the same assertion as the Benign test.

**README and code differ** in most benchmarks: wrong class, button or message names, missing steps, and attack descriptions that the code does not carry out (for example `TaskAffinity-LauncherActivity-PhishingAttack-Lean` is named a phishing attack, but the code shows only a denial of service screen).

**Version drift risks, from reading the code.** Every Testing class is limited with `@SdkSuppress(maxSdkVersion = 27)` or lower, so on API 28 and later the tests are skipped, not failed. The LocalServer certificates that the Networking and Web benchmarks use expired in 2018 and 2019. The build toolchain (Android Gradle plugin 3.1.2, build tools 27.0.3, JDK 8) cannot target current SDKs without porting.

## Next steps

1. Install the six missing x86 system images and create the AVDs, then run phase 1 of the drift study (stock APKs on all seven levels).
2. Run the Benign and Secure tests and the manual checks to confirm or reject each "not yet run" issue, starting with the incomplete Secure fixes above.
3. Draft the two missing models and port one benchmark to a current toolchain to test the target SDK axis.
4. Start the analysis tool, using the ground truth dataset as its test oracle.
