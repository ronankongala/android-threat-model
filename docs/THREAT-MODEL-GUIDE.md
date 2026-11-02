# Threat model guide

This guide explains how to read the threat models in [docs/threat-models/](threat-models/), how to use them to reproduce an exploit, and how to add a new one. It ends with a worked example that walks through [ICC-DynamicRegBroadcastReceiver-UnrestrictedAccess.md](threat-models/ICC-DynamicRegBroadcastReceiver-UnrestrictedAccess.md) section by section.

## Contents

1. [What is in docs/threat-models/](#1-what-is-in-docsthreat-models)
2. [The ten-section template](#2-the-ten-section-template)
3. [STRIDE and LINDDUN](#3-stride-and-linddun)
4. [Attack trees](#4-attack-trees)
5. [The standards mapping table](#5-the-standards-mapping-table)
6. [Using the evidence section to reproduce an exploit](#6-using-the-evidence-section-to-reproduce-an-exploit)
7. [Adding a new threat model](#7-adding-a-new-threat-model)
8. [Worked example: DynamicRegBroadcastReceiver](#8-worked-example-dynamicregbroadcastreceiver)

## 1. What is in docs/threat-models/

| File | Role |
|------|------|
| `ICC-*.md`, `Web-*.md` | 24 full threat models, one per Ghera benchmark in the ICC (16) and Web (8) categories. File names drop the `-Lean` suffix of the benchmark folder: `DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean` becomes `ICC-DynamicRegBroadcastReceiver-UnrestrictedAccess.md`. |
| [TEMPLATE.md](threat-models/TEMPLATE.md) | The ten-section template every model follows. |
| [BATCH-RULES.md](threat-models/BATCH-RULES.md) | The eleven rules that models were written under: sources of claims, standards, evidence wording, mitigation, open questions, style. |
| [standards-reference.md](threat-models/standards-reference.md) | The only allowed CWE, MASVS v2, MASTG and MASWE IDs, each with its official title copied from the official page, its CWE mapping usage, and the date it was checked. |
| [benchmark-index.md](threat-models/benchmark-index.md) | All 57 Ghera benchmarks (tag `Jan2019`) with summary, affected Android versions from the README, draft CWE and MASVS IDs, and a "Model done" column. |
| [other-categories-mapping.md](threat-models/other-categories-mapping.md) | Standards mappings without a full model for the 31 benchmarks in Crypto, Networking, NonAPI, Permission, Storage and System. Each benchmark gets a summary, "What the code does" with file and line pointers, a standards table, candidates to check, an evidence plan, README vs code differences and open questions. |

The "Model done" values in `benchmark-index.md` are `Yes` (full model with observed evidence; only DynamicRegBroadcastReceiver), `Drafted (evidence pending)` (full model, nothing run yet), `Mapped (no full model)` (entry in `other-categories-mapping.md`) and `Not drafted (tool stopped)` (`UnprotectedBroadcastRecv-PrivEscalation-Fat` and `WeakChecksOnDynamicInvocation-DataInjection-Lean`).

The Mermaid diagrams of each model are also rendered to SVG in [docs/diagrams/](diagrams/) by `tools/render_diagrams.py`: block n of `<name>.md` becomes `docs/diagrams/<name>-<n>.svg`. In most models block 1 is the data flow diagram and block 2 the attack tree.

## 2. The ten-section template

Every `ICC-*.md` and `Web-*.md` file has these ten headings, in this order. `tools/lint_docs.py` reports a model that is missing any of them.

| Section | What it holds | How to read it |
|---------|---------------|----------------|
| 1. Benchmark | Name, category, Ghera path, affected Android versions quoted from the README, Ghera tag, date, and a one or two sentence summary. | The scope: which benchmark folder and which Android versions the model is about. |
| 2. System description | A components table (component, app, type, whether other apps can reach it, notes), a trust boundary table (TB1, TB2, ...), and a Mermaid data flow diagram with trust boundaries drawn as subgraphs. | The components table is the quickest way to see what is exported and who talks to whom. |
| 3. Assets and attacker model | Assets and why they matter, who the attacker is, and what the attacker needs (permissions, installation, timing, knowledge, device state). | Read "Attacker requirements" before judging severity: a weakness that needs no permission and no user action is worse than one that needs both. |
| 4. STRIDE | One row per STRIDE category: threat, Applies, Why. | See section 3 below. |
| 5. LINDDUN | One row per LINDDUN category: threat, Applies, Why. | See section 3 below. |
| 6. Attack tree | A Mermaid tree with the attacker goal at the root. | See section 4 below. |
| 7. Standards mapping | CWE, MASVS v2, MASTG test, MASWE and MITRE ATT&CK for Mobile rows, each with ID, exact title, confidence and fit. | See section 5 below. |
| 8. Evidence | Screenshots, the exact build, install and exploit commands, and the observed result for Benign + Malicious and Secure + Malicious. | See section 6 below. In most models this is a plan marked "Not yet run" and "Not yet observed". |
| 9. Mitigation | A Benign vs Secure diff table with file names and lines, and an assessment of whether the fix is complete. | Residual risks are listed even when the Secure app blocks the README exploit. |
| 10. Open questions | README vs code differences, Lean vs Fat differences, and anything unverified. | Claims that could not be backed by the README or the code are kept here rather than in the body (BATCH-RULES rule 1). |

## 3. STRIDE and LINDDUN

Sections 4 and 5 use two threat classification schemes. Each row names a concrete threat for this benchmark, says whether it applies, and gives the reason with a pointer to the code or README.

### STRIDE (security threats)

| Letter | Category | Question asked in the models |
|--------|----------|------------------------------|
| S | Spoofing | Can another app pretend to be a trusted sender or component? |
| T | Tampering | Can an attacker change data the app acts on? |
| R | Repudiation | Can an action happen without a record of who caused it? |
| I | Information disclosure | Can data leak to another app, the network or the user's screen? |
| D | Denial of service | Can an attacker crash the app or block its use? |
| E | Elevation of privilege | Can an app with fewer permissions make the vulnerable app act for it (a confused deputy)? |

### LINDDUN (privacy threats)

| Letter | Category | Question asked in the models |
|--------|----------|------------------------------|
| L | Linkability | Can events or data items be linked to each other, for example usage over time? |
| I | Identifiability | Can the user be identified from the data? |
| N | Non-repudiation | Is the user bound to an action they cannot deny, for example a message sent in their name? |
| D | Detectability | Can an observer tell that an action or data item exists? |
| D | Disclosure of information | Does personal data reach parties it should not? |
| U | Unawareness | Is the user unaware of, or not asked about, what happens to their data? |
| N | Non-compliance | Would the behaviour break data protection rules or consent in a real product? |

Note that STRIDE Repudiation and LINDDUN Non-repudiation look at the same fact from opposite sides: in STRIDE the problem is that the attacker can deny the action, in LINDDUN the problem is that the user cannot.

### The Applies column

Across the 24 models the Applies column uses four values: `Yes` (146 rows), `Partially` (103), `No` (58) and `Yes (not demonstrated)` (5). `Partially` means the threat exists only in part, under a condition, or with limited impact, and the Why cell says which. `Yes (not demonstrated)` means the code shows the threat but no run has shown it. A `No` row still gives the reason, so a missing threat is a decision rather than an omission.

## 4. Attack trees

Section 6 of each model is a Mermaid `flowchart TD` (top down). The root node, usually `G`, states the attacker goal. Edges point from a goal or sub-goal to the steps that achieve it.

How the labels are used in these models:

- A child whose label starts with `AND:` is one of several conditions that must **all** hold for its parent to succeed. In the worked example the root has three `AND:` children: the receiver is reachable, the attacker can deliver a matching broadcast, and the receiver acts on the extras.
- A child whose label starts with `OR:` is one of several **alternatives**; any one of them is enough for its parent. In the worked example "learn action string and extra names" can be done by decompiling the APK or by receiving the app's own broadcast.
- Nodes with no label prefix are leaves: concrete facts or attacker actions, usually tied to a line of code or a README step. Leaves under an `AND:` node are themselves all needed unless they are grouped under `OR:` nodes.

The 24 models contain 78 `AND:` nodes and 50 `OR:` nodes in all. To read a tree, start at the root, find the `AND:` branches (each is a precondition you could break to stop the attack), then look inside each branch for `OR:` alternatives (each must be blocked separately). The Mitigation section usually explains which branch the Secure app cuts.

The data flow diagram in section 2 is also a `flowchart`, drawn left to right (`flowchart LR`). Subgraphs are trust boundaries; solid arrows are flows shown in the code, dotted arrows (`-.->`) are possible or simulated flows.

## 5. The standards mapping table

Section 7 maps the benchmark to standards. Every model uses the same columns:

```text
| Standard | ID | Title | Confidence | Fit |
```

| Column | Meaning |
|--------|---------|
| Standard | `CWE`, `OWASP MASVS v2`, `OWASP MASTG test`, `OWASP MASWE` (and `MITRE ATT&CK for Mobile`, which is handled below the table). |
| ID | A CWE ID (CWE-926), a MASVS v2 control (MASVS-PLATFORM-1), a MASTG test (MASTG-TEST-0366) or a MASWE weakness (MASWE-0018). |
| Title | The official title, copied character for character from [standards-reference.md](threat-models/standards-reference.md). For CWE the `CWE-<n>: ` prefix is left out. For MASVS the "title" is the control statement, for example "The app uses IPC mechanisms securely." |
| Confidence | `Verified` (checked against the official page) or `Needs check`. |
| Fit | `Direct` (the entry describes this benchmark's weakness or test as it is) or `Partial` (it covers part of it, or only with a caveat, which the cell gives). The cell points to the code line that justifies the fit. |

### Which entry is the main one

The table has no separate primary column. `Direct` rows describe the benchmark's weakness as it is and carry the main mapping; `Partial` rows are secondary weaknesses or entries that cover only part of the exploit, and the Fit cell says why. Some models say so in words, for example "Direct. Primary test." on MASTG-TEST-0366 in the DynamicRegBroadcastReceiver model, or "kept only as a secondary, partial entry" in `other-categories-mapping.md`. The docs lint also accepts ID list cells written as `CWE-1395 (primary), CWE-1104` in any table cell, and checks that each ID in them exists in the reference file.

A separate notion of "secondary" exists in the data files: the `secondary_cwe_ids` column of `data/ground-truth.csv` lists CWEs that `tools/evaluate.py` accepts as a match for one of the benchmark's CWEs (for example a CWE-925 finding counts as CWE-926). It comes from the evaluator, not from the models.

### CWE usage levels and DISCOURAGED entries

The CWE table in `standards-reference.md` records each entry's "Usage (mapping notes)" value from the official page:

- **ALLOWED**: can be used directly.
- **ALLOWED-WITH-REVIEW** (CWE-22, CWE-327, CWE-346, CWE-441, CWE-522, CWE-862, CWE-863, CWE-922, CWE-1395): can be used, but the Fit cell must hold the outcome of a mapping notes review: the Rationale and Comment in one sentence, the child entries one level down, and whether a child fits better. The template forbids leaving an instruction to the reader instead.
- **DISCOURAGED** (CWE-20, CWE-200, CWE-284, CWE-345): never placed in a standards table. A model that considered one adds a line under the table, for example "CWE-20 (Improper Input Validation) was considered and is DISCOURAGED in `standards-reference.md`, so it is not in the table; CWE-470 is the more specific entry used instead." (from the FragmentInjection model).

MASTG v1 tests carry a "Deprecated" status in the reference file; a model that uses one says so in the Fit cell (for example "Deprecated, superseded by MASTG v2 tests, kept for reference."). MITRE ATT&CK for Mobile is written as "No direct match" with a one-sentence reason unless an ID was verified on attack.mitre.org (BATCH-RULES rule 5).

### Why titles must match, and what the lint checks

The reference file is the single source of truth: each title there was copied from the downloaded official page, with the date checked. A title typed from memory or from an older CWE version (CWE 4.x shows bracketed names, for example ('SQL Injection') for CWE-89) would make the model disagree with the source it cites. [tools/lint_docs.py](../tools/lint_docs.py) enforces this for every Markdown file in `docs/threat-models/` and `docs/notes/`:

1. every CWE, MASVS, MASTG and MASWE ID in a table cell exists in `standards-reference.md`, and in a standards table (header starting `| Standard |`) the Title cell equals the reference title exactly;
2. no DISCOURAGED CWE appears in a standards table;
3. each `ICC-*.md` and `Web-*.md` file has the ten section headings of `TEMPLATE.md`;
4. no em dash character and none of the banned words named in BATCH-RULES.md rule 9;
5. every relative Markdown link and image resolves to a file;
6. every Mermaid block starts with a known diagram type and has as many `subgraph` lines as `end` lines.

It exits with code 0 when the only findings are unresolved `docs/screenshots` links or the exempt rule text in `BATCH-RULES.md`.

## 6. Using the evidence section to reproduce an exploit

### File and line pointers

Paths in a model are relative to the benchmark folder `benchmarks/ghera/<Category>/<Benchmark>/` unless shown otherwise, for example `Benign/app/src/main/java/edu/ksu/cs/benign/MainActivity.java` line 20. Use them to check a claim before running anything: open the file at that line and compare it with the quoted code. The Ghera checkout is not part of the repository; it must be cloned to `benchmarks/ghera` at tag `Jan2019` (see `docs/notes/SETUP_LOG.md`).

### Build

Build every project of a benchmark (Benign, Malicious, Secure and any others) with the build script, from the project root:

```powershell
powershell -ExecutionPolicy Bypass -File tools\build_all.ps1 -Filter 'ICC/DynamicRegBroadcastReceiver-*'
```

`-Filter` is a wildcard on `<Category>/<Benchmark>`. The script creates `local.properties` with `sdk.dir=C:/Android/Sdk` if needed, runs `gradlew.bat assembleDebug` with `JAVA_HOME` set to `C:\Android\jdk8`, and appends one row per flavor to `data/build-results.csv` (logs in `data/build-logs/`). The APKs land in `<App>\app\build\outputs\apk\<flavor>\debug\app-<flavor>-debug.apk`; the project uses the `api27` flavor. The models' Commands sections show the equivalent manual build (`. .\env.ps1`, then `.\gradlew.bat assembleDebug` in each app folder).

### Emulator

Dot-source `env.ps1`, start the `ghera27` AVD (Android 8.1, API 27, created by `tools/create_avds.ps1`) and check it with `adb devices`:

```powershell
. .\env.ps1
emulator -avd ghera27
adb devices
```

### Run the pairs

Follow the Commands section of the model. Each model has two pairs: Benign + Malicious (the exploit should work) and Secure + Malicious (it should not). Benign and Secure usually share a package name, so uninstall Benign before installing Secure. The model lists the manual steps (taken from the benchmark README), often an `adb shell am broadcast` or `adb shell am start` line that triggers the weakness without the Malicious app, and the expected result from the README and the `Testing` instrumentation code. Compare what you see with the "Observed result" table; in models still marked "Not yet run", fill it in only after a real run.

### Replay the README automatically

[tools/readme_runner.py](../tools/readme_runner.py) parses the numbered "Steps to build the sample apps and to exploit the vulnerability" in a Ghera README and replays them over adb: install the built `api27` APKs, launch apps, tap buttons by their text, press back, and run backticked `adb` commands. After each step it captures logcat and the foreground activity. Nothing other than adb (and aapt to read package names) is executed.

```powershell
python tools\readme_runner.py benchmarks\ghera\ICC\DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean --dry-run
python tools\readme_runner.py benchmarks\ghera\ICC\DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean --json out.json
```

`--dry-run` shows the planned actions without a device. The README steps exercise only the Benign app, so the runner covers the Benign + Malicious pair; check the Secure pair by hand.

### The analysis tool

`python src\ate.py --apk <Benign APK>` reports what the static rules find in the same APK, and `--dynamic-two-app <Malicious APK>` installs both apps and reports task hijacks and storage changes. See [TOOL-GUIDE.md](TOOL-GUIDE.md).

## 7. Adding a new threat model

1. **Pick the benchmark** from [benchmark-index.md](threat-models/benchmark-index.md). Full models exist for ICC and Web; the other categories are covered by `other-categories-mapping.md`.
2. **Copy the template**: copy `docs/threat-models/TEMPLATE.md` to `docs/threat-models/<Category>-<Benchmark>.md`, using `ICC-` or `Web-` and the folder name without `-Lean`, for example `ICC-StickyBroadcast-DataInjection.md`. The `ICC-*` and `Web-*` prefix is what makes `tools/lint_docs.py` check the ten headings. Remove the italic guidance lines when a section is done.
3. **Follow [BATCH-RULES.md](threat-models/BATCH-RULES.md)**. In short: every statement comes from the README or the source code, anything else goes in Open questions (rule 1); write at the depth of `ICC-NoValidityCheckOnBroadcastMsg-UnintendedInvocation.md` with valid Mermaid (rule 2); evidence claims no observed result and is marked "Not yet run" and "Not yet observed" until a real run (rule 6); mitigation diffs Benign and Secure with exact files and lines, and labels any claim about newer Android versions "Hypothesis, to test in Step 3" (rule 7); list README vs code and Lean vs Fat differences (rule 8); no em dashes and no banned words (rule 9); never modify anything under `benchmarks/` (rule 10); add new benchmark issues to `docs/notes/benchmark-issues.md` (rule 11).
4. **Verify every ID** in section 7 against `standards-reference.md`, and copy its title from there. If a CWE you need is missing, add it first: download the official page, fill the row from the raw HTML, and record the usage level (rule 3). For ALLOWED-WITH-REVIEW or DISCOURAGED entries do the mapping notes review and record the outcome. MASTG and MASWE IDs must also be in the reference file (rule 4).
5. **Run the lint** and fix every blocking finding:

   ```powershell
   python tools\lint_docs.py
   ```

6. **Render the diagrams** if Mermaid is set up (`python tools\render_diagrams.py docs\threat-models\<file>.md`), so `docs/diagrams/` has the SVGs.
7. **Update [benchmark-index.md](threat-models/benchmark-index.md)**: set the "Model done" cell of the benchmark's row (for example `Drafted (evidence pending)`), and the Draft CWE and MASVS cells if the model settled them. The `model_file` column of `data/ground-truth.csv` points to the model file for each benchmark.

## 8. Worked example: DynamicRegBroadcastReceiver

The model [ICC-DynamicRegBroadcastReceiver-UnrestrictedAccess.md](threat-models/ICC-DynamicRegBroadcastReceiver-UnrestrictedAccess.md) is the only one with observed evidence ("Model done" is `Yes` in the index). Quotes below are copied from it.

### Section 1: Benchmark

The table gives the Ghera path `benchmarks/ghera/ICC/DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean`, the README range "Tested on Android 5.1.1 - Android 8.1", tag `Jan2019` (commit `6289f39d`) and the build flavors `api22` to `api27` and `apiDIST`. The summary states the weakness in two sentences: the Benign app "registers a broadcast receiver at runtime with `registerReceiver(receiver, filter)` and no permission", so any app that sends the matching action can make it show an "email will be sent" screen "without holding any permission".

### Section 2: System description

The components table lists four components. The key row is `EmailBroadcastRecv`: "Broadcast receiver, registered dynamically", reachable "Yes, while `MainActivity` is alive", and its `onReceive` "copies the `email` and `text` extras into an explicit intent and starts `EmailActivity`. No check of sender or extras." Two trust boundaries are drawn: TB1, the Benign sandbox against other apps (crossed by broadcasts with action `edu.ksu.cs.action.EMAIL`), and TB2, the Benign app against the email recipient. In the data flow diagram the Malicious app's broadcast and Benign's own broadcast both go through "ActivityManager broadcast dispatch" into the receiver; a dotted arrow shows that Benign's broadcast can also reach "Any app with a receiver for edu.ksu.cs.action.EMAIL", which is a second issue next to the README one.

### Section 3: Assets and attacker model

Assets include "The send-email capability of Benign" and the "Integrity of email recipient and body". The attacker is "A third-party app installed on the same device" with "No Android permissions". The requirements also note a timing condition: "Benign's `MainActivity` must be alive (created and not yet destroyed), because the receiver exists only between `onCreate` and `onDestroy`."

### Section 4: STRIDE

Five rows are `Yes` or `Yes (not demonstrated)` and one is `Partially`:

- Spoofing, Yes: "`EmailBroadcastRecv.onReceive` never checks the sender, and the receiver was registered without a permission".
- Tampering, Yes: the extras "are copied unchanged into the intent for `EmailActivity`".
- Repudiation, Yes: "Benign keeps no log of the broadcast origin".
- Information disclosure, Yes (not demonstrated): `MainActivity` sends its own diagnostic data with "an implicit `sendBroadcast(intent)` with no receiver permission and no target package".
- Denial of service, Partially: flooding the action keeps starting `EmailActivity`; "Not tested."
- Elevation of privilege, Yes: "An app with no permissions makes Benign do a privileged action (send email) for it. A confused deputy."

### Section 5: LINDDUN

The privacy view is weaker because the benchmark uses fixed data. Identifiability is `Partially`: `text` holds `"I am " + username`, and "Here the username is the constant `"user"`, but in a real app it would identify the person." Non-repudiation is `Yes` (the recipient sees a message from Benign that the user did not write), Unawareness is `Yes` ("there is no confirmation step"), and Non-compliance is `Partially` ("Out of scope for a synthetic benchmark that processes no real personal data").

### Section 6: Attack tree

The goal is "make Benign send an email with attacker-chosen recipient and text". It has three `AND:` children, all required:

1. "receiver is reachable": the receiver is registered, `MainActivity` is not destroyed, and it was "registered without a permission".
2. "attacker can deliver a matching broadcast", which has two `OR:` sub-goals inside it: "learn action string and extra names" (decompile the APK, or receive Benign's own broadcast) and "send broadcast" (from a malicious app with no permissions, or from `adb shell am broadcast` for testing).
3. "receiver acts on the extras": no sender check, no validation, and no confirmation in `EmailActivity`.

Breaking any one `AND:` branch stops the attack. The Secure app breaks branch 1 by adding a permission to the registration. The rendered tree is [docs/diagrams/ICC-DynamicRegBroadcastReceiver-UnrestrictedAccess-2.svg](diagrams/ICC-DynamicRegBroadcastReceiver-UnrestrictedAccess-2.svg).

### Section 7: Standards mapping

| Row | Fit, as written in the model | Reading |
|-----|------------------------------|---------|
| CWE-926 Improper Export of Android Application Components | "Direct. A dynamically registered receiver is exported by default." | The main weakness. |
| CWE-925 Improper Verification of Intent by Broadcast Receiver | "Partial. The official description is about receivers that trust system intents, while this receiver listens for a custom action." | Related, with a caveat. |
| CWE-927 Use of Implicit Intent for Sensitive Communication | "Partial. Applies only to Benign's own diagnostic broadcast." | The second issue, not the README exploit. |
| MASVS-PLATFORM-1 | Direct | The IPC control. |
| MASTG-TEST-0366 | "Direct. Primary test." | The test to run. |
| MASTG-TEST-0029 | "Partial. Deprecated, superseded by MASTG v2 tests, kept for reference." | Deprecated v1 test. |
| MASWE-0018 | Direct, pointing to "Benign `MainActivity.java` line 20" and its `registerReceiver(...)` call with no permission. | Weakness entry with a code pointer. |
| MASWE-0032 | Partial, "Applies only to Benign's own implicit diagnostic broadcast (`MainActivity.java` line 33, `sendBroadcast(intent)`)". | Second issue. |

Below the table, MITRE ATT&CK for Mobile is "no direct match": T1404 "was considered and rejected" because it covers OS exploitation, "while this is a confused deputy between two apps with no OS vulnerability."

### Section 8: Evidence

The two code pointers can be checked first: in the Benign source, `MainActivity.java` line 20 is `registerReceiver(emailBroadcastRecv, new IntentFilter("edu.ksu.cs.action.EMAIL"));` and line 33 is `sendBroadcast(intent);`. The Commands section then gives the build (`. .\env.ps1` and `.\gradlew.bat assembleDebug` in `Benign`, `Malicious` and `Secure`), the install lines for both pairs (with `adb uninstall edu.ksu.cs.benign` before installing Secure, since it "shares the package name"), and five manual steps: open Benign, press Home, open Malicious, tap SEND BROADCAST, check Benign for the message. It also gives the broadcast without the Malicious app, marked "Not run":

```powershell
adb shell am broadcast -a edu.ksu.cs.action.EMAIL --es email rookie@malicious.com --es text "I can send email without any permissions"
```

Observed results: for Benign + Malicious, "Benign displayed "An email will be sent to rookie@malicious.comwith the text : I can send email without any permissions"" (the missing space comes from `EmailActivity.java`); for Secure + Malicious, "Secure showed no message", and logcat showed a `Permission Denial: broadcasting Intent { act=edu.ksu.cs.action.EMAIL ... } from edu.ksu.cs.malicious ... requires edu.ksu.cs.perm due to registered receiver ...` line. Screenshots: [exploit works on Benign](screenshots/step01_21_exploit-success-benign.png), [no effect on Secure](screenshots/step01_25_exploit-fails-secure.png), [Permission Denial in logcat](screenshots/step01_26_secure-permission-denial-log.png).

The analysis tool agrees with the static part of the model. A run of `python src\ate.py` on the `api27` Benign APK on 2026-11-02 reported `no_validity_check` (CWE-925) and a `taint-flow` (CWE-926, `getStringExtra` to `startActivity`) in `EmailBroadcastRecv`, and `implicit_broadcast` (CWE-927) in `MainActivity$1`. Those are the three CWEs of the model's table.

### Section 9: Mitigation

The diff table shows two changes: the Secure manifest declares `<permission android:name="edu.ksu.cs.perm" android:protectionLevel="dangerous" />`, and `MainActivity.onCreate` registers with `registerReceiver(emailBroadcastRecv, new IntentFilter("edu.ksu.cs.action.EMAIL"), "edu.ksu.cs.perm", null);`. The assessment says the fix "blocks the benchmark exploit but leaves residual risk": the `dangerous` level is weak ("Any app can add `<uses-permission android:name="edu.ksu.cs.perm" />`"; `signature` would be stronger), the implicit broadcast is still sent, `onReceive` still trusts its extras, and stronger alternatives include `setPackage(getPackageName())` or, on API 33 and later, `Context.RECEIVER_NOT_EXPORTED`.

### Section 10: Open questions

Two items: the README says the email is sent "when the user leaves the particular activity", but the code sends it when the button is tapped ("The model follows the code"), and on API 23 and later the Secure app needs a runtime grant of its own dangerous permission before its own broadcast reaches its receiver, which the smoke test did not check.
