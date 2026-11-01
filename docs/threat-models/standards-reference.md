# Standards reference

Official titles for every CWE and MASVS v2 ID used in the threat models and the benchmark index. Each row was checked by opening the official page on the date shown.

## CWE

Titles are copied from the page heading. The CWE pages were served as CWE version 5.0 (shown in the page title).

| ID | Official title | Abstraction level | URL | Date checked | Status |
|---|---|---|---|---|---|
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | Base | https://cwe.mitre.org/data/definitions/22.html | 2026-10-31 | Verified |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | Base | https://cwe.mitre.org/data/definitions/89.html | 2026-10-31 | Verified |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | Class | https://cwe.mitre.org/data/definitions/200.html | 2026-10-31 | Verified |
| CWE-248 | Uncaught Exception | Base | https://cwe.mitre.org/data/definitions/248.html | 2026-10-31 | Verified |
| CWE-250 | Execution with Unnecessary Privileges | Base | https://cwe.mitre.org/data/definitions/250.html | 2026-10-31 | Verified |
| CWE-272 | Least Privilege Violation | Base | https://cwe.mitre.org/data/definitions/272.html | 2026-10-31 | Verified |
| CWE-284 | Improper Access Control | Pillar | https://cwe.mitre.org/data/definitions/284.html | 2026-10-31 | Verified |
| CWE-295 | Improper Certificate Validation | Base | https://cwe.mitre.org/data/definitions/295.html | 2026-10-31 | Verified |
| CWE-297 | Improper Validation of Certificate with Host Mismatch | Variant | https://cwe.mitre.org/data/definitions/297.html | 2026-10-31 | Verified |
| CWE-319 | Cleartext Transmission of Sensitive Information | Base | https://cwe.mitre.org/data/definitions/319.html | 2026-10-31 | Verified |
| CWE-321 | Use of Hard-coded Cryptographic Key | Variant | https://cwe.mitre.org/data/definitions/321.html | 2026-10-31 | Verified |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | Class | https://cwe.mitre.org/data/definitions/327.html | 2026-10-31 | Verified |
| CWE-329 | Generation of Predictable IV with CBC Mode | Variant | https://cwe.mitre.org/data/definitions/329.html | 2026-10-31 | Verified |
| CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | Base | https://cwe.mitre.org/data/definitions/359.html | 2026-10-31 | Verified |
| CWE-441 | Unintended Proxy or Intermediary | Class | https://cwe.mitre.org/data/definitions/441.html | 2026-10-31 | Verified |
| CWE-470 | Use of Externally-Controlled Input to Select Classes or Code | Base | https://cwe.mitre.org/data/definitions/470.html | 2026-10-31 | Verified |
| CWE-494 | Download of Code Without Integrity Check | Base | https://cwe.mitre.org/data/definitions/494.html | 2026-10-31 | Verified |
| CWE-522 | Insufficiently Protected Credentials | Class | https://cwe.mitre.org/data/definitions/522.html | 2026-10-31 | Verified |
| CWE-760 | Use of a One-Way Hash with a Predictable Salt | Variant | https://cwe.mitre.org/data/definitions/760.html | 2026-10-31 | Verified |
| CWE-862 | Missing Authorization | Class | https://cwe.mitre.org/data/definitions/862.html | 2026-10-31 | Verified |
| CWE-863 | Incorrect Authorization | Class | https://cwe.mitre.org/data/definitions/863.html | 2026-10-31 | Verified |
| CWE-922 | Insecure Storage of Sensitive Information | Class | https://cwe.mitre.org/data/definitions/922.html | 2026-10-31 | Verified |
| CWE-925 | Improper Verification of Intent by Broadcast Receiver | Variant | https://cwe.mitre.org/data/definitions/925.html | 2026-10-31 | Verified |
| CWE-926 | Improper Export of Android Application Components | Variant | https://cwe.mitre.org/data/definitions/926.html | 2026-10-31 | Verified |
| CWE-927 | Use of Implicit Intent for Sensitive Communication | Variant | https://cwe.mitre.org/data/definitions/927.html | 2026-10-31 | Verified |
| CWE-1104 | Use of Unmaintained Third Party Components | Base | https://cwe.mitre.org/data/definitions/1104.html | 2026-10-31 | Verified |
| CWE-1395 | Dependency on Vulnerable Third-Party Component | Class | https://cwe.mitre.org/data/definitions/1395.html | 2026-10-31 | Verified |

Note: the page headings for CWE-22 and CWE-89 do not include the parenthetical short names ("Path Traversal", "SQL Injection") that older CWE versions carried in the title. The titles above match the headings as they appear on the pages.

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

No CWE in the list above is marked deprecated. Two are marked DISCOURAGED for vulnerability mapping in their "Vulnerability Mapping" field:

- CWE-200 (Class): DISCOURAGED. The page says this ID should not be used to map to real-world vulnerabilities. Rows that use it (`OpenSocket-InformationLeak-Lean`, `ClipboardUse-InformationExposure-Lean`) need a more specific child CWE.
- CWE-284 (Pillar): DISCOURAGED. The page says this ID should not be used to map to real-world vulnerabilities. Rows that use it (`InadequatePathPermission-InformationExposure-Lean`, `WeakPermission-UnauthorizedAccess-Lean`) need a more specific child CWE.

These IDs are marked ALLOWED-WITH-REVIEW, meaning they can be used only in limited situations after careful review of the mapping notes: CWE-22, CWE-327, CWE-441, CWE-522, CWE-862, CWE-863, CWE-922, CWE-1395. All other IDs above are marked ALLOWED.
