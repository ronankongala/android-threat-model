# Standards reference

Official titles for every CWE and MASVS v2 ID used in the threat models and the benchmark index, and for the CWE IDs the threat models considered but could not use. Each row was checked by opening the official page on the date shown.

## CWE

Each CWE page was downloaded as raw HTML on 2026-10-31. The "Official title" column is the text of the page's `<h2>` heading, copied character for character. The "Page label" column is the value shown next to the "Vulnerability Mapping" label in the status block at the top of each page, also copied character for character. The "Usage (mapping notes)" column is the value in the "Usage" row of the "Vulnerability Mapping Notes" section further down each page, copied character for character. The "Abstraction level" column is the value shown next to the "Abstraction" label in the same block. Raw HTML was obtained for all 30 pages, so no row is marked "Needs check". CWE-20, CWE-345 and CWE-532 were added later on the same date, from newly downloaded raw HTML, because the ICC broadcast threat models needed them.

CWE version: the version string on every page is `(5.0)`. It appears at the end of the page's `<title>` element (for example `CWE-89: Improper Neutralization of Special Elements used in an SQL Command (5.0)`) and again at the end of the breadcrumb line at the top of the page. It does not appear in the `<h2>` heading.

| ID | Official title | Abstraction level | Page label | Usage (mapping notes) | URL | Date checked | Status |
|---|---|---|---|---|---|---|---|
| CWE-20 | CWE-20: Improper Input Validation | Class | DISCOURAGED | DISCOURAGED | https://cwe.mitre.org/data/definitions/20.html | 2026-10-31 | Verified |
| CWE-22 | CWE-22: Improper Limitation of a Pathname to a Restricted Directory | Base | ALLOWED | ALLOWED-WITH-REVIEW | https://cwe.mitre.org/data/definitions/22.html | 2026-10-31 | Verified |
| CWE-89 | CWE-89: Improper Neutralization of Special Elements used in an SQL Command | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/89.html | 2026-10-31 | Verified |
| CWE-200 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor | Class | DISCOURAGED | DISCOURAGED | https://cwe.mitre.org/data/definitions/200.html | 2026-10-31 | Verified |
| CWE-248 | CWE-248: Uncaught Exception | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/248.html | 2026-10-31 | Verified |
| CWE-250 | CWE-250: Execution with Unnecessary Privileges | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/250.html | 2026-10-31 | Verified |
| CWE-272 | CWE-272: Least Privilege Violation | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/272.html | 2026-10-31 | Verified |
| CWE-284 | CWE-284: Improper Access Control | Pillar | DISCOURAGED | DISCOURAGED | https://cwe.mitre.org/data/definitions/284.html | 2026-10-31 | Verified |
| CWE-295 | CWE-295: Improper Certificate Validation | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/295.html | 2026-10-31 | Verified |
| CWE-297 | CWE-297: Improper Validation of Certificate with Host Mismatch | Variant | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/297.html | 2026-10-31 | Verified |
| CWE-319 | CWE-319: Cleartext Transmission of Sensitive Information | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/319.html | 2026-10-31 | Verified |
| CWE-321 | CWE-321: Use of Hard-coded Cryptographic Key | Variant | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/321.html | 2026-10-31 | Verified |
| CWE-327 | CWE-327: Use of a Broken or Risky Cryptographic Algorithm | Class | ALLOWED | ALLOWED-WITH-REVIEW | https://cwe.mitre.org/data/definitions/327.html | 2026-10-31 | Verified |
| CWE-329 | CWE-329: Generation of Predictable IV with CBC Mode | Variant | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/329.html | 2026-10-31 | Verified |
| CWE-345 | CWE-345: Insufficient Verification of Data Authenticity | Class | DISCOURAGED | DISCOURAGED | https://cwe.mitre.org/data/definitions/345.html | 2026-10-31 | Verified |
| CWE-359 | CWE-359: Exposure of Private Personal Information to an Unauthorized Actor | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/359.html | 2026-10-31 | Verified |
| CWE-441 | CWE-441: Unintended Proxy or Intermediary | Class | ALLOWED | ALLOWED-WITH-REVIEW | https://cwe.mitre.org/data/definitions/441.html | 2026-10-31 | Verified |
| CWE-470 | CWE-470: Use of Externally-Controlled Input to Select Classes or Code | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/470.html | 2026-10-31 | Verified |
| CWE-494 | CWE-494: Download of Code Without Integrity Check | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/494.html | 2026-10-31 | Verified |
| CWE-522 | CWE-522: Insufficiently Protected Credentials | Class | ALLOWED | ALLOWED-WITH-REVIEW | https://cwe.mitre.org/data/definitions/522.html | 2026-10-31 | Verified |
| CWE-532 | CWE-532: Insertion of Sensitive Information into Log File | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/532.html | 2026-10-31 | Verified |
| CWE-760 | CWE-760: Use of a One-Way Hash with a Predictable Salt | Variant | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/760.html | 2026-10-31 | Verified |
| CWE-862 | CWE-862: Missing Authorization | Class | ALLOWED | ALLOWED-WITH-REVIEW | https://cwe.mitre.org/data/definitions/862.html | 2026-10-31 | Verified |
| CWE-863 | CWE-863: Incorrect Authorization | Class | ALLOWED | ALLOWED-WITH-REVIEW | https://cwe.mitre.org/data/definitions/863.html | 2026-10-31 | Verified |
| CWE-922 | CWE-922: Insecure Storage of Sensitive Information | Class | ALLOWED | ALLOWED-WITH-REVIEW | https://cwe.mitre.org/data/definitions/922.html | 2026-10-31 | Verified |
| CWE-925 | CWE-925: Improper Verification of Intent by Broadcast Receiver | Variant | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/925.html | 2026-10-31 | Verified |
| CWE-926 | CWE-926: Improper Export of Android Application Components | Variant | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/926.html | 2026-10-31 | Verified |
| CWE-927 | CWE-927: Use of Implicit Intent for Sensitive Communication | Variant | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/927.html | 2026-10-31 | Verified |
| CWE-1104 | CWE-1104: Use of Unmaintained Third Party Components | Base | ALLOWED | ALLOWED | https://cwe.mitre.org/data/definitions/1104.html | 2026-10-31 | Verified |
| CWE-1395 | CWE-1395: Dependency on Vulnerable Third-Party Component | Class | ALLOWED | ALLOWED-WITH-REVIEW | https://cwe.mitre.org/data/definitions/1395.html | 2026-10-31 | Verified |

Titles are as shown in CWE 5.0; older versions such as 4.20 show bracketed names, for example ('SQL Injection') for CWE-89 (checked in `cwec_v4.20.xml` from https://cwe.mitre.org/data/archive.html).

Note on mapping status: for eight IDs (CWE-22, CWE-327, CWE-441, CWE-522, CWE-862, CWE-863, CWE-922, CWE-1395), the label next to "Vulnerability Mapping" reads ALLOWED, but the hover text on that label reads "This CWE ID could be used to map to real-world vulnerabilities in limited situations requiring careful review", and the "Usage" row in the "Vulnerability Mapping Notes" section further down the same page reads ALLOWED-WITH-REVIEW. The "Page label" column records the label and the "Usage (mapping notes)" column records the Usage row. Treat these eight as needing a review of their mapping notes before use.

## MASVS v2

MASVS controls have no separate name, so the official title is the control statement shown under the control ID on its page.

| ID | Official title | URL | Date checked | Status |
|---|---|---|---|---|
| MASVS-STORAGE-1 | The app securely stores sensitive data. | https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/ | 2026-10-31 | Verified |
| MASVS-STORAGE-2 | The app prevents leakage of sensitive data. | https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/ | 2026-10-31 | Verified |
| MASVS-CRYPTO-1 | The app employs current strong cryptography and uses it according to industry best practices. | https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/ | 2026-10-31 | Verified |
| MASVS-CRYPTO-2 | The app performs key management according to industry best practices. | https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/ | 2026-10-31 | Verified |
| MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices. | https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/ | 2026-10-31 | Verified |
| MASVS-NETWORK-2 | The app performs identity pinning for all remote endpoints under the developer's control. | https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/ | 2026-10-31 | Verified |
| MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. | https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/ | 2026-10-31 | Verified |
| MASVS-PLATFORM-2 | The app uses WebViews securely. | https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/ | 2026-10-31 | Verified |
| MASVS-PLATFORM-3 | The app uses the user interface securely. | https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/ | 2026-10-31 | Verified |
| MASVS-CODE-3 | The app only uses software components without known vulnerabilities. | https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/ | 2026-10-31 | Verified |
| MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs. | https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/ | 2026-10-31 | Verified |
| MASVS-PRIVACY-1 | The app minimizes access to sensitive data and resources. | https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/ | 2026-10-31 | Verified |
| MASVS-PRIVACY-2 | The app prevents identification of the user. | https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-2/ | 2026-10-31 | Verified |

## Replaced entries

Built from the "Usage (mapping notes)" column only. The label conflict for eight IDs is explained in the note under the CWE table.

### DISCOURAGED or PROHIBITED

No row has a Usage of PROHIBITED. Four rows have a Usage of DISCOURAGED. On all four pages the Usage row reads "(this CWE ID should not be used to map to real-world vulnerabilities)".

- CWE-200 (Class): DISCOURAGED. Rows that use it (`OpenSocket-InformationLeak-Lean`, `ClipboardUse-InformationExposure-Lean`) need a more specific child CWE.
- CWE-284 (Pillar): DISCOURAGED. Rows that use it (`InadequatePathPermission-InformationExposure-Lean`, `WeakPermission-UnauthorizedAccess-Lean`) need a more specific child CWE.
- CWE-20 (Class): DISCOURAGED. No threat model table or benchmark index row uses it. `NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean` considered it for the receiver that accepts any intent. The mapping notes give the reasons Frequent Misuse, Frequent Misinterpretation and Abstraction, and say to consider lower-level children if the issue is truly improper input validation.
- CWE-345 (Class): DISCOURAGED. No threat model table or benchmark index row uses it. `OrderedBroadcast-DataInjection-Lean` and `StickyBroadcast-DataInjection-Lean` considered it for receivers that trust data from an unknown sender. The mapping notes give the reason Abstraction (a level-1 Class) and say to examine its children for a better fit.

### ALLOWED-WITH-REVIEW

Eight rows have a Usage of ALLOWED-WITH-REVIEW. On each page the Usage row reads "(this CWE ID could be used to map to real-world vulnerabilities in limited situations requiring careful review)". Read the mapping notes on the page before using these IDs.

- CWE-22 (Base)
- CWE-327 (Class)
- CWE-441 (Class)
- CWE-522 (Class)
- CWE-862 (Class)
- CWE-863 (Class)
- CWE-922 (Class)
- CWE-1395 (Class)
