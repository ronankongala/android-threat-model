# Real-world app case study

Run of `src/ate.py` (static layers only) on five open source Android apps from F-Droid, and of `src/privacy_checker.py` on the same apps with their published privacy statements. Date: 2026-11-02.

## Apps and method

| App | Package | Version (code) | Category | Google Play installs |
|-----|---------|----------------|----------|---------------------:|
| Loop Habit Tracker | `org.isoron.uhabits` | 2.3.2 (20302) | Health, habits | 5M+ |
| Tasks.org | `org.tasks` | 15.12 (151202) | Productivity | 500K+ |
| Markor | `net.gsantner.markor` | 2026.10.0 (164) | Productivity, notes | 100K+ |
| OpenTracks | `de.dennisguse.opentracks` | v4.29.0 (6766) | Health, sport tracking | 10K+ |
| drip | `com.drip` | 1.2601.11 (51) | Health, cycle tracking | 100K+ |

- **APKs**: the F-Droid suggested version of each app, downloaded from `https://f-droid.org/repo/<package>_<versionCode>.apk` into `data/real-world-apks/` (gitignored). F-Droid publishes no install counts, so the counts come from each app's Google Play listing (OpenTracks is listed on Play as `de.dennisguse.opentracks.playstore`). The F-Droid builds can differ from the Play builds; Tasks.org in particular ships without Google services on F-Droid.
- **Static run**: `python src/ate.py --apk data/real-world-apks/<apk> --out data/real-world-reports`. `ate.py` has no `--no-dynamic` flag; static analysis only is its default. Reports: `data/real-world-reports/<package>_<versionCode>-report.{json,md}`.
- **Manual review**: for each finding, the decoded manifest (intent filters, permissions, protection levels) and the flagged smali lines were read, together with the app's description and documentation. Nothing was run on a device, so a "confirmed" verdict means the weakness is present in the code and manifest, not that an exploit was demonstrated.

Verdicts used below:
- **Confirmed**: the reported weakness is present and reachable by another app or by content from outside the app.
- **By design**: the component is exposed on purpose (a documented plugin or public API) without caller checks. It matches the Ghera weakness, but the app accepts the risk.
- **False positive**: the pattern matched, but the code or manifest shows the weakness is not there or has no security effect.

## Findings

### Loop Habit Tracker (`org.isoron.uhabits`)

16 findings in 16 components.

| # | Finding | Component | CWE | Verdict | Review note | Ghera pattern |
|---|---------|-----------|-----|---------|-------------|---------------|
| 1 | exported-no-permission | `EditHabitActivity` | CWE-926 | Confirmed (low impact) | `exported="true"` with no intent filter and no permission. Any app can open the habit editor; the user must still save the change. | ICC exported component (as in `UnprotectedBroadcastRecv-PrivEscalation-Lean`) |
| 2 | exported-no-permission | `ListHabitsActivity` | CWE-926 | Confirmed (low impact) | Same: explicitly exported, no filter. It is the target of the launcher alias, so exporting it is not needed. | as above |
| 3 to 5 | exported-no-permission | `HabitPickerDialog`, `BooleanHabitPickerDialog`, `NumericalHabitPickerDialog` | CWE-926 | False positive | Widget configuration activities (`APPWIDGET_CONFIGURE`) must be exported for the launcher. | none |
| 6 | task-affinity-hijack | `SnoozeDelayPickerActivity` | CWE-1021 | False positive | `singleInstance` dialog with the default affinity. No shared affinity and no reparenting, which the Ghera TaskAffinity attacks need. | `TaskAffinity-ActivityHijack-Lean` (rule matched, condition absent) |
| 7 | exported-no-permission | `EditSettingActivity` | CWE-926 | By design | Locale/Tasker plugin edit screen (`com.twofortyfouram.locale.intent.action.EDIT_SETTING`). | ICC exported component |
| 8 to 13 | exported-no-permission | six `*WidgetProvider` receivers | CWE-926 | False positive | App widget providers (`APPWIDGET_UPDATE`); an external update only redraws the widget. | none |
| 14 | exported-no-permission | `ReminderReceiver` | CWE-926 | Confirmed (low impact) | Filter for `BOOT_COMPLETED`, which only the system can send, but the receiver is exported, so any app can send it an explicit intent and trigger reminder rescheduling. | `NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean` |
| 15 | exported-no-permission | `FireSettingReceiver` | CWE-926 | By design | Locale/Tasker plugin action. Any app can send it the fire intent and change habit check marks. | `UnprotectedBroadcastRecv-PrivEscalation-Lean` |
| 16 | implicit_broadcast | `ReminderController` | CWE-927 | False positive | The broadcast is `android.intent.action.CLOSE_SYSTEM_DIALOGS` with no data. | `ImplicitPendingIntent`/`StickyBroadcast` family (rule matched, no data sent) |

Not reported by the tool: `WidgetReceiver` is exported with `android:permission="false"`, so the permission's name is the literal string "false". No app declares that permission. If Android accepts a permission with that name from another app, a malicious app could declare it, hold it, and send `ACTION_TOGGLE_REPETITION` or `ACTION_SET_NUMERICAL_VALUE` to the receiver. This was read in the manifest and not tested. It resembles the permission name mismatch in the Ghera Secure apps (`docs/notes/secure-app-bugs.md`). The tool treats any non-empty permission as protection, so it cannot see this.

### Markor (`net.gsantner.markor`)

12 findings in 10 components.

| # | Finding | Component | CWE | Verdict | Review note | Ghera pattern |
|---|---------|-----------|-----|---------|-------------|---------------|
| 1 | exported-no-permission | `SettingsActivity` | CWE-926 | False positive | `APPLICATION_PREFERENCES` entry point for the system settings screen. | none |
| 2 | exported-no-permission | `WrWidgetConfigure` | CWE-926 | False positive | Widget configuration activity. | none |
| 3 | exported-no-permission | `DocumentActivity` | CWE-926 | By design, see 8 | Opens files for `SEND`, `VIEW`, `EDIT`, and `VIEW` with category `BROWSABLE`. A web page or any app can hand Markor a document to display. | `Web-UnsafeIntentURLImpl` (entry point) |
| 4 | exported-no-permission | `AliasDocumentProcessText` | CWE-926 | False positive | `PROCESS_TEXT` text selection action. | none |
| 5, 6 | exported-no-permission | `WrMarkorWidgetProvider`, `TodoWidgetProvider` | CWE-926 | False positive | App widget providers. | none |
| 7 | certificate_pinning_missing | application | CWE-295 | Confirmed (low impact) | `usesCleartextTraffic="true"` and no network security config. The README says the network is used only for external resources a user's document references (for example an image URL), so those loads can be read or changed on the network. | `HttpConnection-MITM-Lean`, `UnpinnedCertificates-MITM-Lean` |
| 8 | js_enabled | `DocumentEditAndViewFragment` | CWE-749 | Plausible, not confirmed | The preview WebView enables JavaScript and registers the fragment as a JavaScript interface named `Android` (one `@JavascriptInterface` method, `webViewJavascriptCallback(String[])`). Markdown can contain HTML, and documents arrive from other apps and the browser (finding 3), so script in a document can call the bridge. The callback's effect was not traced. | `Web-JavaScriptExecution-CodeInjection`, `Web-WebViewInterceptRequest-MITM` (bridge) |
| 9 | webview_file_access | `DocumentEditAndViewFragment` | CWE-829 | Partly confirmed | `setAllowFileAccess(true)` and `setAllowContentAccess(true)`, but `setAllowFileAccessFromFileURLs(false)` and `setAllowUniversalAccessFromFileURLs(false)`. Script can load local files into the page, but cannot read them across origins, which the Ghera exploit needs. | `Web-WebViewAllowFileAccess-UnauthorizedFileAccess` |
| 10 | directory_traversal | `GsContextUtils` | CWE-22 | False positive | `new File(dir, name)` in a file manager helper; the name comes from the user's own folder browsing. | `DirectoryTraversal` (Storage) |
| 11 | implicit_broadcast | `GsContextUtils` | CWE-927 | False positive | Legacy `INSTALL_SHORTCUT` broadcast to the launcher, carrying a shortcut name and icon only. | as Loop 16 |
| 12 | taint-flow | `AttachLinkOrFileDialog` | CWE-22 | False positive | Source is an `EditText` the user types a path into; the user is not an attacker against their own files. | `DirectoryTraversal` |

### OpenTracks (`de.dennisguse.opentracks`)

11 findings in 11 components.

| # | Finding | Component | CWE | Verdict | Review note | Ghera pattern |
|---|---------|-----------|-----|---------|-------------|---------------|
| 1 to 3 | exported-no-permission | `publicapi.StartRecording`, `StopRecording`, `CreateMarker` | CWE-926 | By design | The README documents a Public API that is "disabled by default" and is enabled in settings. Once enabled, any app can start or stop GPS recording with an explicit intent. | `UnprotectedBroadcastRecv-PrivEscalation-Lean` (unprotected trigger) |
| 4 | exported-no-permission | `HealthConnectPermissionsRationaleActivity` | CWE-926 | False positive | Required by Health Connect (`ACTION_SHOW_PERMISSIONS_RATIONALE`). | none |
| 5 | exported-no-permission | `ImportActivity` | CWE-926 | By design | Share and open target for track files (`SEND`, `VIEW` with `BROWSABLE`). Parsing untrusted GPX/KML files is attack surface, but the export itself is intended. | none |
| 6, 7 | exported-no-permission | `ShowMarkerActivity`, `CreateMarkerActivity` | CWE-926 | Confirmed (low impact) | Custom actions (`de.dennisguse.opentracks.MarkerDetails`, `CreateMarker`) with no permission; any app can open them and pass a marker or track ID. | ICC exported component |
| 8 | task-affinity-hijack | `ShowErrorActivity` | CWE-1021 | False positive | `singleInstance`, default affinity, not exported. | as Loop 6 |
| 9 | exported-no-permission | `HealthDataSdkService` | CWE-926 | False positive | AndroidX Health Connect client service; the library checks callers. | none |
| 10 | sql_injection_raw | `CustomContentProvider` | CWE-89 | False positive | The flagged `execSQL` runs the constant `"VACUUM"`. The provider is not exported. | `SQLite-execSQL` (Storage) |
| 11 | taint-flow | `ShowErrorActivity` | CWE-926 | False positive | The error text from a `TextView` goes into an `ACTION_SEND` share intent that the user starts to report a crash. That is the intended data flow. | `ImplicitPendingIntent-IntentHijack` (implicit intent with data) |

### drip (`com.drip`)

5 findings in 5 components.

| # | Finding | Component | CWE | Verdict | Review note | Ghera pattern |
|---|---------|-----------|-----|---------|-------------|---------------|
| 1 | task-affinity-hijack | `MainActivity` | CWE-1021 | False positive | Launcher activity with `singleTask` and the default affinity. | as Loop 6 |
| 2 | implicit_broadcast | `RNPushNotificationActions` | CWE-927 | False positive | React Native push library; the broadcast is `CLOSE_SYSTEM_DIALOGS` with no data. | as Loop 16 |
| 3 | unique_ids | `AndroidInfoModule` | CWE-359 | False positive | React Native framework reads `Settings.Secure.ANDROID_ID`. drip requests no `INTERNET` permission, so the value cannot leave the device through the app. | `UniqueIDs-IdentityLeak-Lean` |
| 4, 5 | implicit_broadcast | `SonyHomeBadger`, `VivoHomeBadger` | CWE-927 | False positive | ShortcutBadger library sends the unread badge count to the launcher. The count is the only data. | as Loop 16 |

### Tasks.org (`org.tasks`)

56 findings: 30 from the manifest and 26 from code. The full scan took 28 minutes, most of it in the taint layer.

Manifest findings:

| Findings | Finding | Component | CWE | Verdict | Review note | Ghera pattern |
|---|---------|-----------|-----|---------|-------------|---------------|
| 2 | exported-no-permission | `Astrid2TaskProvider`, `TasksContentProvider` (and `TaskProvider`, not reported) | CWE-926 | Confirmed (weak protection) | Exported public task API. Reads need `org.tasks.permission.READ_TASKS`, which Tasks.org declares with `protectionLevel="dangerous"`: any app can request it and the user only has to accept a prompt. `insert`, `update` and `delete` have no `writePermission`, but the code shows they are stubs (return 0 or null, or throw "not supported"), so writes are not exposed. The tool reports these providers because `android:permission` is unset; it does not read `readPermission`. | `DynamicRegBroadcastReceiver-UnrestrictedAccess-Lean` Secure (a `dangerous` permission as the guard), `InadequatePathPermission-InformationExposure-Lean` |
| 2 | exported-no-permission, path-not-sanitized | `WidgetIconProvider` | CWE-926, CWE-22 | False positive | Exported with `grantUriPermissions` and no permission, but `openFile` accepts only mode `"r"` (else `SecurityException("Only read access allowed")`) and checks the name against `^[a-zA-Z0-9_]+$` before opening a cache file. It serves generated widget icons. | `InadequatePathPermission` (rule matched, path is sanitized) |
| 3 | task-affinity-hijack | `ShareLinkActivity` (`:share`), `SnoozeActivity` (`:snooze`), `NotificationActivity` (`:notification`) | CWE-1021 | Matches the Ghera pattern, not tested | Non-default task affinities, the condition the Ghera hijack uses: a malicious app that declares the same affinity can place its activity in the victim's task. A leading colon is expanded with the package name, so the affinity is predictable. `ShareLinkActivity` is also exported (share target). | `TaskAffinity-ActivityHijack-Lean` |
| 4 | task-affinity-hijack | `MainActivity`, `WidgetClickActivity`, `AuthorizationManagementActivity`, `TrustCertificateActivity` | CWE-1021 | False positive | `singleTask` or `singleInstance` with the default affinity. | as Loop 6 |
| 1 | exported-no-permission | `RedirectUriReceiverActivity` | CWE-926 | By design | AppAuth OAuth redirect target (browsable `VIEW`). Must be reachable from the browser; AppAuth checks the `state` parameter. | `Web-UnsafeIntentURLImpl` (entry point) |
| 1 | exported-no-permission | `UriHandler` | CWE-926 | By design | Handles `tasks.org` and `tasks://` links (`VIEW`). | as above |
| 2 | exported-no-permission | `TaskerCreateTaskActivity`, `PluginActivity` (alias) | CWE-926 | By design | Locale/Tasker plugin edit screens. | ICC exported component |
| 1 | exported-no-permission | `FireReceiver` | CWE-926 | By design | Locale/Tasker plugin action: any app can send it a fire intent that creates a task. | `UnprotectedBroadcastRecv-PrivEscalation-Lean` |
| 4 | exported-no-permission | `SystemEventReceiver`, `ScheduleExactAlarmsPermissionReceiver`, `MyPackageReplacedReceiver`, `LocationProviderChangedReceiver` | CWE-926 | Confirmed (low impact) | Filters for system broadcasts (`BOOT_COMPLETED`, `USER_PRESENT`, `MY_PACKAGE_REPLACED`, `PROVIDERS_CHANGED`, and the exact alarm permission change), but exported, so any app can send an explicit intent and trigger rescheduling. | `NoValidityCheckOnBroadcastMsg-UnintendedInvocation-Lean` |
| 1 | exported-no-permission | `MainActivity` | CWE-926 | False positive | Main entry (`MAIN`), reached through the launcher aliases. | none |
| 6 | exported-no-permission | `FilterSelectionActivity`, `IconPickerActivity`, `ShortcutConfigActivity`, `WidgetConfigActivity`, `DashClockSettings`, `NotificationPreferences` | CWE-926 | False positive | Widget, shortcut and DashClock configuration, and the system notification settings link. `FilterSelectionActivity` and `IconPickerActivity` have no filter and return a selection to the caller, which reveals only list names. | none |
| 1 | exported-no-permission | `TrustCertificateActivity` | CWE-926 | Needs review | cert4android screen that asks the user to trust a server certificate for CalDAV sync; exported with no filter. Another app can open it, but the decision stays with the user. | `CheckValidity-InformationExposure-Lean` (certificate trust) |
| 1 | exported-no-permission | `ShareLinkActivity` | CWE-926 | By design | Share target (`SEND`, `PROCESS_TEXT`). | none |
| 1 | exported-no-permission | `TasksWidget` | CWE-926 | False positive | App widget provider. | none |

Code findings:

| Findings | Finding | Component | CWE | Verdict | Review note | Ghera pattern |
|---------:|---------|-----------|-----|---------|-------------|---------------|
| 1 | implicit_broadcast | `org.tasks.pebble.PebbleProtocol` | CWE-927 | Plausible, not confirmed | `sendToPebble` sends `com.getpebble.action.app.SEND` with a `msg_data` JSON payload and no `setPackage`, so any app that registers for that action receives what Tasks.org sends to the Pebble watch app. Only when the Pebble integration is in use; the payload contents were not traced. | `StickyBroadcast-DataInjection-Lean`, `OrderedBroadcast-DataInjection-Lean` (data in an unprotected broadcast) |
| 1 | implicit_broadcast | `PebbleService$register$receiver$1` | CWE-927 | False positive | Acknowledgement broadcast with a transaction ID only. | as Loop 16 |
| 2 | implicit_broadcast | `SonyHomeBadger`, `VivoHomeBadger` | CWE-927 | False positive | ShortcutBadger library, badge count only (as in drip). | as Loop 16 |
| 1 | implicit_broadcast | `org.dmfs.provider.tasks.Utils` | CWE-927 | Needs review | OpenTasks provider library sends change notifications built from an iterator; the intent targets were not traced. | as above |
| 4 | sql_injection_raw | `TableColumns`, `TaskDatabaseHelper`, osmdroid `SqlTileWriter` (2) | CWE-89 | False positive | `PRAGMA table_info(<internal table name>)`, constant schema migrations (`ALTER TABLE Tasks ADD COLUMN is_new INTEGER`), and the osmdroid map tile cache. | `SQLite-RawQuery`, `SQLite-execSQL` (Storage) |
| 1 | sql_injection_no_args | `org.dmfs.provider.tasks.TaskProvider` | CWE-89 | False positive | Selection is `"_id=" + <long>`, which cannot carry SQL. | `SQLite-SQLInjection` (Storage) |
| 13 | sql_injection_no_args | other `org.dmfs.provider.tasks` handlers, adapters and processors | CWE-89 | Likely false positive (not reviewed one by one) | The OpenTasks library builds its selections internally, as in the sampled `TaskProvider` case. The provider does pass a calling app's own `selection` to SQLite, which is the normal `ContentProvider` contract; callers need the `dangerous` `READ_TASKS` or `WRITE_TASKS` permission. | as above |
| 3 | sql_injection_no_args | `CalendarProvider`, `OpenTaskDao` (2) | CWE-89 | False positive | Client-side `ContentResolver.query` calls to the calendar and OpenTasks providers; Tasks.org is the caller, not the provider. | none |

## Summary of the static findings

| App | Findings | Confirmed | Plausible or matches a Ghera pattern (not tested) | By design | Needs review | False positive |
|-----|---------:|----------:|---------:|----------:|-------------:|---------------:|
| Loop Habit Tracker | 16 | 3 | 0 | 2 | 0 | 11 |
| Markor | 12 | 1 | 2 | 1 | 0 | 8 |
| OpenTracks | 11 | 2 | 0 | 4 | 0 | 5 |
| drip | 5 | 0 | 0 | 0 | 0 | 5 |
| Tasks.org | 56 | 6 | 4 | 6 | 2 | 38 |
| **Total** | **100** | **12** | **6** | **13** | **2** | **67** |

The Tasks.org false positives include 13 "likely" ones that were sampled, not reviewed one by one. Counting only confirmed and plausible findings as useful, 18 of 100 findings (0.18) point at a real weakness. Counting the by-design exposures too, since they match the Ghera weakness and an analyst would want to see them, 31 of 100 (0.31). None of the confirmed findings is high impact: the worst are a JavaScript bridge reachable from browsable intents (Markor), task data behind a `dangerous` permission (Tasks.org), and unauthenticated plugin and API triggers.

## Comparison with the Ghera benchmarks

The Ghera evaluation (`docs/notes/evaluation-report.md`) predicts a precision near 0.5, mostly because any exported component is reported. The real apps show the same effect more strongly:

- **Exported components dominate.** Most findings are `exported-no-permission` (CWE-926). In Ghera, an exported component is usually the vulnerability itself. In real apps, most exported components are entry points the platform requires: launcher aliases, widget providers and widget configuration screens, share targets, settings links. The rule does not tell these apart from the Ghera kind of exposure. A filter for platform-only actions (`APPWIDGET_UPDATE`, `APPWIDGET_CONFIGURE`, `APPLICATION_PREFERENCES`, `MAIN`/`LAUNCHER`, `PROCESS_TEXT`) would remove most of these false positives. Whether it costs any Ghera true positive was not checked; that needs a rerun of `tools/evaluate.py --no-dynamic` with the filter in place.
- **Library code adds noise.** Ghera apps have no third-party libraries. In the real apps, 25 of the 39 code findings come from libraries (React Native, ShortcutBadger, the OpenTasks provider, osmdroid). Of the 10 `implicit_broadcast` hits, 9 are `CLOSE_SYSTEM_DIALOGS`, launcher badge or shortcut intents, or acknowledgements with no private data; only the Tasks.org Pebble broadcast carries app data. The 17 `sql_injection_no_args` hits on Tasks.org come almost entirely from one library that builds its own selections.
- **The rules match patterns, not conditions.** `task-affinity-hijack` now fires on any `singleTask` or `singleInstance` activity (Fix C), but the Ghera TaskAffinity attacks need a shared or empty affinity or reparenting. None of the real apps' hits has that, so all are false positives. The Ghera set could not show this, because no Ghera app sets `launchMode`.
- **Where the tool helps.** The findings worth a closer look are the ones Ghera trains for: the Markor WebView with JavaScript, file access and a JavaScript bridge, opened from browsable intents (`Web-JavaScriptExecution`, `Web-WebViewAllowFileAccess`); unprotected trigger components (OpenTracks Public API, Loop and Tasks.org plugin receivers, as in `UnprotectedBroadcastRecv`); and cleartext traffic (Markor, as in `HttpConnection-MITM`).
- **What it misses.** The tool did not report Loop's `android:permission="false"`. It treats any `android:permission` value as protection, whatever its name or protection level, which is the same gap behind its false negatives on Ghera Secure apps with weak or mismatched permissions. It did report the Tasks.org providers, but for the wrong reason: it ignores `readPermission` and `writePermission`, so it calls them unprotected, when the actual weakness is that the guard is a `dangerous` permission.

## Privacy policy analysis

Run of `src/privacy_checker.py` (the check behind `ate.py --policy`) on each APK with its published privacy statement, on 2026-11-02. Results: `data/real-world-reports/privacy/<package>_<versionCode>-privacy.{json,md}`. The policy texts used are saved in `data/real-world-reports/privacy/policies/`, each with its source URL.

**Where the policies came from.** F-Droid package pages carry no privacy policy; they link to each app's website and source repository. Loop, drip and Tasks.org publish a policy page on their website. Markor and OpenTracks have no separate policy; the "Privacy" section of the README in the source repository that F-Droid links to was used instead. The Tasks.org page loads its text from Termly at run time, so the text was taken from the Termly content API for the policy embedded on `tasks.org/privacy`.

The run called `apk.decode` and `privacy_checker.check` directly, the same calls `ate.py --policy` makes, without the code and taint layers, which the privacy check does not use and which take up to 30 minutes per app.

| App | Negative claims recognized in the policy | INTERNET | Ad or analytics SDK | Contradictions | Verdict |
|-----|------------------------------------------|:--------:|:-------------------:|---------------:|---------|
| Loop Habit Tracker | data stored only on the device; not shared with 3rd parties; no advertisement or analytics code | no | none | 0 | Consistent |
| Tasks.org | not sold or shared to third parties in the last 12 months (CCPA wording) | yes | none | 0 | Consistent (policy discloses location, analytics and service providers) |
| Markor | works offline, "no internet connection required"; no data shared with third parties | yes | none | 1 (medium) | False positive |
| OpenTracks | "No Internet access"; no advertising; no in-app analytics | no | none | 0 | Consistent |
| drip | data stored only on the device; no ads, no tracking | no | none | 0 | Consistent |

**Review of the one contradiction.** Markor's README says "The app works completely offline, no internet connection required!" and the manifest requests `INTERNET`. The same README lists `INTERNET` under its permissions, used when "user-generated content data can be loaded from the internet" (an image URL in a note). The claim is that the app needs no connection, not that it never uses one, so this is a false positive of the keyword rule. It is reported as medium, not high, because no SDK gives the data a way out. The cleartext setting found in the static run (Markor finding 7) is the more useful observation: the loads the README mentions may go over plain HTTP.

**What the check found and missed.**
- The three apps that claim no network use (Loop, OpenTracks, drip) indeed request no `INTERNET` permission, and none of the five F-Droid builds contains an advertising or analytics SDK package. F-Droid's inclusion policy forbids proprietary tracking libraries, so this result is expected for this source; Play Store builds would be a harder test.
- Tasks.org's policy is a generic template that covers the website, the Play build and the paid sync service. It makes no negative claim the manifest could contradict, so the checker has nothing to compare. Its location permissions (`ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`) are disclosed ("We may request access or permission to track location-based information").
- Running on real policies exposed three gaps in the keyword rules, fixed in `src/privacy_checker.py` with tests: "3rd parties" was not read as "third parties" (Loop), Markdown emphasis such as `__No Internet access:__` hid claims (OpenTracks), and a hyphenated word such as "in-app" broke the "no analytics" claim (OpenTracks).
- Claims about data the manifest cannot show (for example drip's "We do not collect, retain, or share any usage data") are out of scope: there is no permission or package to compare them with.
