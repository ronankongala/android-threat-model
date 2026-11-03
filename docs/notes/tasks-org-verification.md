# Tasks.org — manual verification of high-confidence findings

Source report: `data/real-test/org.tasks_151202-report.md` (32 high-confidence findings).

Source checked: https://github.com/tasks/tasks at tag `15.12` (commit `1211fc4`, `versionCode = 151202`, which matches the analyzed APK exactly). Third-party library code was checked against tasks/opentasks at commit `44e5ce6b82` (the pinned version) and osmdroid 6.1.20 / master. Line numbers refer to the 15.12 tree. `Manifest` means `app/src/main/AndroidManifest.xml`.

How each verdict was decided:
- **True Positive**: another installed app can cause real harm with no user involvement.
- **Informational**: the flagged condition exists in the code but can't realistically be exploited, or it is required by design.
- **False Positive**: the condition isn't present, or it is fully mitigated.

| # | Component | Issue | Verdict | Reason |
|---|---|---|---|---|
| 1 | net.openid.appauth.RedirectUriReceiverActivity | exported-no-permission | Informational | An OAuth redirect receiver has to be exported and BROWSABLE (Manifest 178-193). AppAuth discards any response whose `state` doesn't match a pending request, so an injected redirect is dropped. |
| 2 | org.tasks.compose.FilterSelectionActivity | exported-no-permission | Informational | It is a picker UI (FilterSelectionActivity.kt:55-148). It returns or applies a filter only after the user selects one, so nothing happens without user interaction. |
| 3 | org.tasks.compose.IconPickerActivity | exported-no-permission | Informational | It reads no meaningful input and only returns the icon name the user picks via `setResult` (IconPickerActivity.kt:40-66). |
| 4 | org.tasks.activities.UriHandler | exported-no-permission | Informational | VIEW handler for `content://org.tasks` task URIs (UriHandler.kt:25-59). It only opens the task editor on screen; it returns no data to the caller and changes nothing without the user. |
| 5 | org.tasks.widget.ShortcutConfigActivity | exported-no-permission | Informational | A standard `CREATE_SHORTCUT` config UI (Manifest 262-271). The user picks a filter and theme in the UI, and it reads no extras an attacker could abuse. |
| 6 | com.todoroo.astrid.activity.ShareLinkActivity | exported-no-permission | Informational | It is an intentional SEND/PROCESS_TEXT share target. It pre-fills the task editor instead of saving silently. Attachments are restricted to `content://` URIs from other apps' providers (ShareLinkActivity.kt:100-106). |
| 7 | com.todoroo.astrid.activity.ShareLinkActivity | task-affinity-hijack | False Positive | `taskAffinity=":share"` resolves to the app's own `org.tasks:share` affinity, and the activity is `excludeFromRecents`. That is not the StrandHogg pattern of a default affinity that allows reparenting. |
| 8 | org.tasks.widget.WidgetConfigActivity | exported-no-permission | Informational | An `APPWIDGET_CONFIGURE` activity must be exported for the launcher. It finishes immediately without a valid widget ID (WidgetConfigActivity.kt:17-30) and otherwise only opens a settings UI. |
| 9 | org.tasks.reminders.SnoozeActivity | task-affinity-hijack | False Positive | It is not exported: no `exported` attribute and no intent-filter (Manifest 457-461). The `":snooze"` affinity is package-private. |
| 10 | org.tasks.reminders.NotificationActivity | task-affinity-hijack | False Positive | It is not exported: no `exported` attribute and no intent-filter (Manifest 463-467). The `":notification"` affinity is package-private. |
| 11 | org.tasks.dashclock.DashClockSettings | exported-no-permission | Informational | It is the `settingsActivity` of the DashClock extension (Manifest 602-607), which has to be exported. It does not handle any intent extras. |
| 12 | org.tasks.locale.ui.activity.TaskerCreateTaskActivity | exported-no-permission | Informational | It is the standard Locale/Tasker `EDIT_SETTING` plugin screen (Manifest 626-637). It only builds a config bundle and returns it to the caller. |
| 13 | com.todoroo.astrid.activity.MainActivity | exported-no-permission | Informational | It is the launcher activity. Its extras (MainActivity.kt:581-592) can at most open a filter or editor, or create a blank task, and nothing is returned to the caller. |
| 14 | org.tasks.preferences.NotificationPreferences | exported-no-permission | Informational | Its `NOTIFICATION_PREFERENCES` filter (Manifest 704-712) is the standard hook from system notification settings. It does not handle any intent extras. |
| 15 | at.bitfire.cert4android.TrustCertificateActivity | exported-no-permission | **True Positive** | It is exported with no permission (cert4android manifest:9-13). `processIntent` (TrustCertificateActivity.kt:92-101) accepts an attacker-supplied `certificate` extra, and when `trusted=true` it calls `registerDecision(true)` with no UI. That calls `CustomCertStore.setTrustedByUser`, which saves the cert to the user keystore that the app's OkHttp client trusts. Any app can therefore silently plant a trusted cert and set up a MITM of CalDAV/WebDAV sync. |
| 16 | com.twofortyfouram.locale.example.setting.toast.ui.activity.PluginActivity | exported-no-permission | Informational | It is an activity-alias for the Tasker plugin settings screen with the Locale `EDIT_SETTING` filter (Manifest 650-658), exported by design. |
| 17 | org.tasks.widget.TasksWidget (receiver) | exported-no-permission | Informational | An AppWidgetProvider must be exported for the launcher (Manifest 333-347). A spoofed `APPWIDGET_UPDATE` only redraws the widget. |
| 18 | org.tasks.receivers.SystemEventReceiver | exported-no-permission | False Positive | It handles only the protected system broadcasts `BOOT_COMPLETED` and `USER_PRESENT` (Manifest 524-531) and ignores all other actions, so it can't be spoofed. |
| 19 | org.tasks.receivers.ScheduleExactAlarmsPermissionReceiver | exported-no-permission | False Positive | It handles only the protected `SCHEDULE_EXACT_ALARM_PERMISSION_STATE_CHANGED` broadcast (Manifest 533-539) and returns early on any other action. |
| 20 | org.tasks.receivers.MyPackageReplacedReceiver | exported-no-permission | False Positive | It handles only the protected `MY_PACKAGE_REPLACED` broadcast (Manifest 543-549) and just re-enqueues geofence registration. |
| 21 | org.tasks.receivers.LocationProviderChangedReceiver | exported-no-permission | False Positive | It handles only the protected `PROVIDERS_CHANGED` broadcast, is `enabled="false"` by default (Manifest 570-577), and only re-registers geofences. |
| 22 | org.tasks.locale.receiver.FireReceiver | exported-no-permission | Informational | It is the Locale/Tasker `FIRE_SETTING` plugin API, open by design. Another app can inject tasks or notifications through it but can't read any data back. |
| 23 | org.tasks.widget.WidgetIconProvider | exported-no-permission | Informational | The report's "query and modify" claim is wrong. query, insert, update and delete are no-ops. `openFile` is read-only, only accepts names matching `^[a-zA-Z0-9_]+$`, and serves public generated icon PNGs. |
| 24 | org.dmfs.provider.tasks.utils.TableColumns | sql_injection_raw | Informational | `rawQuery("PRAGMA table_info(%s)")` escapes the table name with `sqlEscapeString`, and the only caller passes the constant `Tables.TASKS` (TaskDatabaseHelper.java:840). |
| 25 | org.osmdroid.tileprovider.modules.MapTileFileStorageProviderBase | dynamic_receiver_no_permission | False Positive | The dynamic receiver listens only for the protected `MEDIA_MOUNTED`/`MEDIA_UNMOUNTED` broadcasts and only toggles tile storage. |
| 26 | org.osmdroid.tileprovider.modules.SqlTileWriter$1 | sql_injection_raw | Informational | The cleanup `rawQuery` (SqlTileWriter.java:688-695) is built only from constants, `currentTimeMillis()` and an int bulk size, so no external input reaches it. |
| 27 | org.tasks.compose.settings.ShortcutWidgetHelperKt | pending_intent_mutable | False Positive | The flags are `if (atLeastS()) FLAG_MUTABLE else FLAG_UPDATE_CURRENT` (ShortcutWidgetHelper.kt:171), so 0x8000000 is only the pre-S branch. The explicit `RequestPinWidgetReceiver` intent is intentionally mutable for the `requestPinAppWidget` callback. |
| 28 | org.tasks.location.LocationServiceAndroid | pending_intent_mutable | False Positive | On S+ it passes `FLAG_MUTABLE or FLAG_UPDATE_CURRENT` (LocationServiceAndroid.kt:106-114), which geofencing requires, and the intent is explicit. |
| 29 | org.tasks.location.LocationUpdateReceiver$Companion | pending_intent_mutable | False Positive | On S+ it passes `FLAG_MUTABLE or FLAG_UPDATE_CURRENT` (kmp/.../LocationUpdateReceiver.kt:22-30), with an explicit intent handed to the location client. |
| 30 | org.tasks.pebble.PebbleService | dynamic_receiver_no_permission | **True Positive** | It registers a receiver for the unprotected `com.getpebble.action.app.RECEIVE` with `RECEIVER_EXPORTED` and no permission, unconditionally at app start (PebbleService.kt:35-39, TasksApplication.kt:201). Any app that knows the public `APP_UUID` can send `MSG_COMPLETE_TASK`/`MSG_SAVE_TASK` and complete or modify the user's tasks. |
| 31 | org.tasks.preferences.fragments.Widgets | pending_intent_mutable | False Positive | The flags are `if (atLeastS()) FLAG_MUTABLE else FLAG_UPDATE_CURRENT` (Widgets.kt:70-75), on an explicit `RequestPinWidgetReceiver` callback intent. |
| 32 | org.tasks.widget.TasksWidget (class) | pending_intent_mutable | False Positive | The flagged call is `getPendingIntentTemplate` (TasksWidget.kt:198-207). On S+ it passes `FLAG_MUTABLE or FLAG_UPDATE_CURRENT`, wraps an explicit `WidgetClickActivity` intent, and is used for `setPendingIntentTemplate`, which requires a mutable PendingIntent. |

## Summary

| Verdict | Count |
|---|---|
| True Positive | 2 |
| Informational | 17 |
| False Positive | 13 |
| **Total high-confidence** | **32** |

- **Precision of high-confidence findings, counting only exploitable issues as correct: 2 / 32 = 6.3%.**
- If findings whose flagged condition is real are also counted as correct (TP + Informational), precision is 19 / 32 = 59.4%.

### Where the false positives come from
- **pending_intent_mutable (5 of 5 are FP):** the rule reads one constant from smali and misses runtime `if (atLeastS())` flag selection. On API 31+ a PendingIntent without either mutability flag throws at creation, so the claimed state can't exist on targetSdk 36.
- **exported receivers that only accept protected broadcasts (4) and the dynamic osmdroid receiver (1):** the rule doesn't check whether the intent-filter actions can only be sent by the system.
- **task-affinity-hijack with a `:`-prefixed affinity (3):** these affinities resolve to the app's own package, and two of the three activities aren't exported at all.

### Where the informational findings come from
Most exported activities are entry points the platform requires: launcher, share target, widget config, OAuth redirect, and Tasker/DashClock plugins. Flagging them is technically correct but almost never actionable. A per-component exploitability check (does it read extras and act on them without UI?) would separate the two real issues (#15, #30) from this noise.

### Notes
- The two true positives were confirmed by reading the code statically, not by running an exploit on a device.
- TrustCertificateActivity (#15) and PebbleService (#30) appear to be genuine issues worth reporting upstream to Tasks.org / cert4android.
