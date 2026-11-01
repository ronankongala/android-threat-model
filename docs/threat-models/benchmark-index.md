# Ghera benchmark index

Total: 57 benchmarks (Crypto 5, ICC 18, Networking 8, NonAPI 2, Permission 2, Storage 7, System 7, Web 8).

Source: `benchmarks/ghera` at tag `Jan2019`. The `Misc` and `TemplateCategory` folders are not benchmarks and are skipped.

The Draft CWE and Draft MASVS control columns are first guesses based on the README only. None of them has been checked against the official sources, so every row is marked "Needs check". "None" means no confident guess.

The "Android versions affected" text is copied from each README. Most READMEs use the heading "Android versions affected"; a few use "Versions of Android affected".

## Crypto (5)

| Category | Folder name | Lean or Fat | Summary | Android versions affected | Draft CWE | Draft MASVS control | Confidence | Model done |
|---|---|---|---|---|---|---|---|---|
| Crypto | `BlockCipher-ECB-InformationExposure-Lean` | Lean | Using a block cipher in ECB mode to encrypt sensitive data can leak information about the plaintext. | Tested on Android 5.1.1 - Android 8.1 | CWE-327 | MASVS-CRYPTO-1 | Needs check | No |
| Crypto | `BlockCipher-NonRandomIV-InformationExposure-Lean` | Lean | Using CBC mode with a non-random IV to encrypt sensitive data can leak information. | Tested on Android 5.1.1 - Android 8.1 | CWE-329 | MASVS-CRYPTO-1 | Needs check | No |
| Crypto | `ConstantKey-ForgeryAttack-Lean` | Lean | Hard-coding encryption keys in source code enables forgery and information leaks. | Tested on Android 5.1.1 - Android 8.1 | CWE-321 | MASVS-CRYPTO-2 | Needs check | No |
| Crypto | `ExposedCredentials-InformationExposure-Lean` | Lean | Storing keys without a protection parameter in a keystore other apps can read exposes them. | Tested on Android 5.1.1 - Android 8.1 | CWE-522 | MASVS-CRYPTO-2 | Needs check | No |
| Crypto | `PBE-ConstantSalt-InformationExposure-Lean` | Lean | Using a constant salt for password-based encryption allows dictionary attacks that expose data. | Tested on Android 5.1.1 - Android 8.1 | CWE-760 | MASVS-CRYPTO-1 | Needs check | No |

## ICC (18)

| Category | Folder name | Lean or Fat | Summary | Android versions affected | Draft CWE | Draft MASVS control | Confidence | Model done |
|---|---|---|---|---|---|---|---|---|
| ICC | `DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean` | Lean | A dynamically registered broadcast receiver can be reached by any app unless access is restricted. | Tested on Android 5.1.1 - Android 8.1 | CWE-926 | MASVS-PLATFORM-1 | Needs check | Yes |
| ICC | `EmptyPendingIntent-PrivEscalation-Lean` | Lean | A pending intent with an empty base intent lets the receiving app act with the sender's privileges. | Tested on Android 5.1.1 - Android 8.1 | None | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `FragmentInjection-PrivEscalation-Lean` | Lean | Loading fragments into an activity through reflection allows fragment injection. | Tested on Android 4.4 - Android 7.1 | CWE-470 | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `HighPriority-ActivityHijack-Lean` | Lean | An activity with low intent filter priority can be hijacked by a malicious activity with higher priority. | Tested on Android 5.1.1 - Android 8.1 | CWE-927 | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `ImplicitPendingIntent-IntentHijack-Lean` | Lean | A pending intent with an implicit base intent can be hijacked by another app. | Tested on Android 5.1.1 - Android 8.1 | CWE-927 | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `InadequatePathPermission-InformationExposure-Lean` | Lean | Protecting a content provider with only a path permission can leak its sensitive data. | Tested on Android 5.1.1 - Android 8.1 | CWE-284 | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `IncorrectHandlingImplicitIntent-UnauthorizedAccess-Lean` | Lean | Components that accept implicit intents without handling them correctly allow unauthorized access. | Tested on Android 5.1.1 - Android 8.1 | CWE-926 | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean` | Lean | A receiver for system broadcasts that does not check the message before acting can be triggered by other apps. | Tested on Android 5.1.1 - Android 8.1 | CWE-925 | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `OrderedBroadcast-DataInjection-Lean` | Lean | A receiver of ordered broadcasts can get data injected by a malicious receiver with higher priority. | Tested on Android 5.1.1 - Android 8.1 | CWE-927 | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `StickyBroadcast-DataInjection-Lean` | Lean | Sending sticky broadcasts can leak sensitive data and allows data injection. | Tested on Android 5.1.1 - Android 8.1 | CWE-927 | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `TaskAffinity-ActivityHijack-Lean` | Lean | Activities that can start in a new task can be hijacked through task affinity. | Tested on Android 5.1.1 - Android 8.1 | None | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `TaskAffinity-LauncherActivity-PhishingAttack-Lean` | Lean | A malicious launcher activity using task affinity can run phishing or denial of service attacks on another app. | Tested on Android 5.1.1 - Android 7.1 | None | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `TaskAffinity-PhishingAttack-Lean` | Lean | Activities that can start in a new task are exposed to phishing through task affinity. | Tested on Android 5.1.1 - Android 8.1 | None | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `TaskAffinityAndReparenting-PhishingAndDoSAttack-Lean` | Lean | A malicious app using task reparenting can run phishing or denial of service attacks on another app. | Tested on Android 5.1.1 - Android 8.1 | None | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `UnhandledException-DOS-Lean` | Lean | Not handling unchecked exceptions lets another app crash the component, causing denial of service. | Tested on Android 5.1.1 - Android 8.1 | CWE-248 | MASVS-CODE-4 | Needs check | Drafted (evidence pending) |
| ICC | `UnprotectedBroadcastRecv-PrivEscalation-Fat` | Fat | Exporting components that hold privileged permissions lets other apps escalate privileges. | Tested on Android 4.4 | CWE-926 | MASVS-PLATFORM-1 | Needs check | No |
| ICC | `UnprotectedBroadcastRecv-PrivEscalation-Lean` | Lean | Exporting components that hold privileged permissions lets other apps escalate privileges. | Tested on Android 5.1.1 - Android 8.1 | CWE-926 | MASVS-PLATFORM-1 | Needs check | Drafted (evidence pending) |
| ICC | `WeakChecksOnDynamicInvocation-DataInjection-Lean` | Lean | Exposing call() in a content provider without proper checks allows unauthorized reads and writes of the data store. | Tested on Android 5.1.1 - Android 8.1 | CWE-862 | MASVS-PLATFORM-1 | Needs check | Not drafted (tool stopped) |

## Networking (8)

| Category | Folder name | Lean or Fat | Summary | Android versions affected | Draft CWE | Draft MASVS control | Confidence | Model done |
|---|---|---|---|---|---|---|---|---|
| Networking | `CheckValidity-InformationExposure-Lean` | Lean | Not checking certificate validity when talking to a server exposes information. | Tested on Android 5.1.1 - Android 8.1 | CWE-295 | MASVS-NETWORK-1 | Needs check | No |
| Networking | `IncorrectHostNameVerification-MITM-Lean` | Lean | Not verifying the server host name allows man-in-the-middle attacks. | Tested on Android 5.1.1 - Android 8.1 | CWE-297 | MASVS-NETWORK-1 | Needs check | No |
| Networking | `InsecureSSLSocket-MITM-Lean` | Lean | Using SSLCertificateSocketFactory.getSocket(InetAddress, ...) allows man-in-the-middle attacks. | Tested on Android 5.1.1 - Android 8.1 | CWE-297 | MASVS-NETWORK-1 | Needs check | No |
| Networking | `InsecureSSLSocketFactory-MITM-Lean` | Lean | Using SSLCertificateSocketFactory.getInsecure() allows man-in-the-middle attacks. | Tested on Android 5.1.1 - Android 8.1 | CWE-295 | MASVS-NETWORK-1 | Needs check | No |
| Networking | `InvalidCertificateAuthority-MITM-Lean` | Lean | Not checking the validity of the certificate authority allows man-in-the-middle attacks. | Tested on Android 5.1.1 - Android 8.1 | CWE-295 | MASVS-NETWORK-1 | Needs check | No |
| Networking | `OpenSocket-InformationLeak-Lean` | Lean | Communicating with a remote server over an open port can leak information. | Tested on Android 5.1.1 - Android 8.1 | CWE-200 | MASVS-NETWORK-1 | Needs check | No |
| Networking | `UnEncryptedSocketComm-MITM-Lean` | Lean | Unencrypted TCP/IP communication lets a man-in-the-middle intercept traffic and spoof the server. | Tested on Android 5.1.1 - Android 8.1 | CWE-319 | MASVS-NETWORK-1 | Needs check | No |
| Networking | `UnpinnedCertificates-MITM-Lean` | Lean | Not pinning trusted server certificates allows man-in-the-middle attacks. | Tested on Android 5.1.1 - Android 8.1 | CWE-295 | MASVS-NETWORK-2 | Needs check | No |

## NonAPI (2)

| Category | Folder name | Lean or Fat | Summary | Android versions affected | Draft CWE | Draft MASVS control | Confidence | Model done |
|---|---|---|---|---|---|---|---|---|
| NonAPI | `MergeManifest-UnintendedBehavior-Lean` | Lean | An app can silently inherit exported components from a library manifest during manifest merging. | Tested on Android 5.1.1 - Android 8.1 | CWE-926 | MASVS-PLATFORM-1 | Needs check | No |
| NonAPI | `OutdatedLibrary-DirectoryTraversal-Lean` | Lean | Using an outdated library with known flaws makes the app vulnerable too. | Tested on Android 5.1.1 - Android 8.1 | CWE-1395 (primary), CWE-1104 | MASVS-CODE-3 | Needs check | No |

## Permission (2)

| Category | Folder name | Lean or Fat | Summary | Android versions affected | Draft CWE | Draft MASVS control | Confidence | Model done |
|---|---|---|---|---|---|---|---|---|
| Permission | `UnnecesaryPerms-PrivEscalation-Lean` | Lean | Requesting more permissions than needed enables privilege escalation by other apps. | Tested on Android 5.1.1 - Android 8.1 | CWE-250 | MASVS-PRIVACY-1 | Needs check | No |
| Permission | `WeakPermission-UnauthorizedAccess-Lean` | Lean | Protecting exported components with weak permissions is about as bad as not protecting them. | Tested on Android 5.1.1 - Android 8.1 | CWE-284 | MASVS-PLATFORM-1 | Needs check | No |

## Storage (7)

| Category | Folder name | Lean or Fat | Summary | Android versions affected | Draft CWE | Draft MASVS control | Confidence | Model done |
|---|---|---|---|---|---|---|---|---|
| Storage | `ExternalStorage-DataInjection-Lean` | Lean | Reading files from external storage allows malicious data injection. | Tested on Android 5.1.1 - Android 8.1 | None | MASVS-CODE-4 | Needs check | No |
| Storage | `ExternalStorage-InformationLeak-Lean` | Lean | Writing sensitive data to external storage can leak it. | Tested on Android 5.1.1 - Android 8.1 | CWE-922 | MASVS-STORAGE-1 | Needs check | No |
| Storage | `InternalStorage-DirectoryTraversal-Lean` | Lean | Writing files to internal storage without sanitizing paths allows directory traversal. | Tested on Android 5.1.1 - Android 8.1 | CWE-22 | MASVS-CODE-4 | Needs check | No |
| Storage | `InternalToExternalStorage-InformationLeak-Lean` | Lean | Letting internal storage files be downloaded to external storage can leak them. | Tested on Android 5.1.1 - Android 8.1 | CWE-922 | MASVS-STORAGE-1 | Needs check | No |
| Storage | `SQLite-execSQL-Lean` | Lean | Building non-parameterized queries for SQLiteDatabase.execSQL() allows SQL injection. | Tested on Android 5.1.1 - 8.1 | CWE-89 | MASVS-CODE-4 | Needs check | No |
| Storage | `SQLlite-RawQuery-SQLInjection-Lean` | Lean | Building non-parameterized queries for SQLiteDatabase.rawQuery() allows SQL injection. | Tested on Android 5.1.1 - Android 8.1 | CWE-89 | MASVS-CODE-4 | Needs check | No |
| Storage | `SQLlite-SQLInjection-Lean` | Lean | Building select, update, and delete queries without selectionArgs allows SQL injection. | Tested on Android 5.1.1 - Android 8.1 | CWE-89 | MASVS-CODE-4 | Needs check | No |

## System (7)

| Category | Folder name | Lean or Fat | Summary | Android versions affected | Draft CWE | Draft MASVS control | Confidence | Model done |
|---|---|---|---|---|---|---|---|---|
| System | `CheckCallingOrSelfPermission-PrivilegeEscalation-Lean` | Lean | Using checkCallingOrSelfPermission for access control allows privilege escalation. | Tested on Android 5.1.1 - Android 8.1 | CWE-441 | MASVS-PLATFORM-1 | Needs check | No |
| System | `CheckPermission-PrivilegeEscalation-Lean` | Lean | Using checkPermission for access control allows privilege escalation. | Tested on Android 5.1.1 - Android 8.1 | CWE-863 | MASVS-PLATFORM-1 | Needs check | No |
| System | `ClipboardUse-InformationExposure-Lean` | Lean | Copying sensitive data to the clipboard can leak it. | Tested on Android 5.1.1 - Android 8.1 | CWE-200 | MASVS-STORAGE-2 | Needs check | No |
| System | `DynamicCodeLoading-CodeInjection-Lean` | Lean | Loading code dynamically without checking its integrity and origin allows code injection. | Tested on Android 5.1.1 - Android 8.1 | CWE-494 | None | Needs check | No |
| System | `EnforceCallingOrSelfPermission-PrivilegeEscalation-Lean` | Lean | Using enforceCallingOrSelfPermission for access control allows privilege escalation. | Tested on Android 5.1.1 - Android 8.1 | CWE-441 | MASVS-PLATFORM-1 | Needs check | No |
| System | `EnforcePermission-PrivilegeEscalation-Lean` | Lean | Using enforcePermission for access control allows privilege escalation. | Tested on Android 5.1.1 - Android 8.1 | CWE-863 | MASVS-PLATFORM-1 | Needs check | No |
| System | `UniqueIDs-IdentityLeak-Lean` | Lean | Using device identifiers to identify app instances exposes device-specific sensitive data. | Tested on Android 4.4 - Android 7.1 | CWE-359 | MASVS-PRIVACY-2 | Needs check | No |

## Web (8)

| Category | Folder name | Lean or Fat | Summary | Android versions affected | Draft CWE | Draft MASVS control | Confidence | Model done |
|---|---|---|---|---|---|---|---|---|
| Web | `HttpConnection-MITM-Lean` | Lean | Connecting to a server over plain HTTP allows man-in-the-middle attacks. | Tested on Android 5.1.1 - Android 8.1 | CWE-319 | MASVS-NETWORK-1 | Needs check | No |
| Web | `JavaScriptExecution-CodeInjection-Lean` | Lean | Enabling JavaScript in a WebView that loads arbitrary content can run malicious code. | Tested on Android 5.1 - Android 8.1 | None | MASVS-PLATFORM-2 | Needs check | No |
| Web | `UnsafeIntentURLImpl-InformationExposure-Lean` | Lean | Not sanitizing intents embedded in URIs lets a web page hijack them and expose information. | Tested on Android 5.1.1 - Android 8.1 | None | MASVS-PLATFORM-2 | Needs check | No |
| Web | `WebView-NoUserPermission-InformationExposure-Lean` | Lean | Disclosing sensitive data to web content without asking the user exposes it unintentionally. | Tested on Android 5.1.1 - Android 8.1 | CWE-359 | MASVS-PLATFORM-2 | Needs check | No |
| Web | `WebViewAllowFileAccess-UnauthorizedFileAccess-Lean` | Lean | Running JavaScript of unknown origin in a WebView with file access can expose app files. | Tested on Android 5.1.1 - Android 8.1 | None | MASVS-PLATFORM-2 | Needs check | No |
| Web | `WebViewIgnoreSSLWarning-MITM-Lean` | Lean | Ignoring SSL errors in a WebView allows man-in-the-middle attacks. | Tested on Android 5.1.1 - Android 8.1 | CWE-295 | MASVS-NETWORK-1 | Needs check | No |
| Web | `WebViewInterceptRequest-MITM-Lean` | Lean | Not validating resource requests in shouldInterceptRequest() lets malicious content load in a WebView. | Tested on Android 5.1.1 - Android 8.1 | None | MASVS-PLATFORM-2 | Needs check | No |
| Web | `WebViewOverrideUrl-MITM-Lean` | Lean | Not validating page requests in shouldOverrideUrlLoading() lets malicious pages load in a WebView. | Tested on Android 5.1.1 - Android 8.1 | None | MASVS-PLATFORM-2 | Needs check | No |
