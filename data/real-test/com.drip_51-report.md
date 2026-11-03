# com.drip_51 report

| Component | Type | Issue | CWE | Confidence | Evidence |
|---|---|---|---|---|---|
| com.drip.MainActivity | activity | task-affinity-hijack | CWE-1021 | medium | `android:launchMode="singleTask"` |
| (application) | application | default-task-affinity | CWE-1021 | low | `<application> has no android:taskAffinity and no activity sets one; launcher com.drip.MainActivity uses the default affinity (the package name com.drip)` |
| (application) | application | certificate_pinning_missing | CWE-295 | high | `no network security config, usesCleartextTraffic unset; network call invoke-interface {v0}, Lokhttp3/Call;->cancel()V` |
| cl.json.ShareFile | class | external_storage_io | CWE-922 | medium | `invoke-direct {v0, v4}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V` |
| cl.json.ShareFiles | class | external_storage_io | CWE-922 | medium | `invoke-direct {v5, v6}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V` |
| cl.json.social.TargetChosenReceiver | class | dynamic_receiver_no_permission | CWE-926 | high | `invoke-virtual {v2, v3, v4}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent; [no broadcastPermission argument: any app can send this receiver a broadcast]` |
| cl.json.social.TargetChosenReceiver | class | pending_intent_mutable | CWE-927 | high | `invoke-static {p0, v0, v1, v2}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent; [flags 0x50000000: neither FLAG_IMMUTABLE nor FLAG_MUTABLE; required for apps targeting API 31+ (targetSdkVersion 34), a mutable PendingIntent lets the receiving app fill in its Intent]` |
| com.dieam.reactnativepushnotification.modules.RNPushNotificationActions | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {p1, p2}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V` |
| com.dieam.reactnativepushnotification.modules.RNPushNotificationHelper | class | pending_intent_mutable | CWE-927 | high | `invoke-static {v2, v0, v1, p1}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent; [flags 0x8000000: neither FLAG_IMMUTABLE nor FLAG_MUTABLE; required for apps targeting API 31+ (targetSdkVersion 34), a mutable PendingIntent lets the receiving app fill in its Intent]` |
| com.drip.MainApplication | class | dynamic_receiver_no_permission | CWE-926 | high | `invoke-super {p0, p1, p2, v0}, Landroid/app/Application;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)Landroid/content/Intent; [no broadcastPermission argument: any app can send this receiver a broadcast]` |
| com.facebook.react.devsupport.DevSettingsActivity | class | fragment_injection | CWE-470 | medium | `.super Landroid/preference/PreferenceActivity;` |
| com.facebook.react.devsupport.DevSupportManagerBase | class | dynamic_receiver_no_permission | CWE-926 | high | `invoke-virtual {v2, v3, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent; [no broadcastPermission argument: any app can send this receiver a broadcast]` |
| com.facebook.react.modules.systeminfo.AndroidInfoModule | class | unique_ids | CWE-359 | high | `invoke-static {v0, v1}, Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;` |
| me.leolin.shortcutbadger.impl.SonyHomeBadger | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {p0, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V` |
| me.leolin.shortcutbadger.impl.VivoHomeBadger | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {p1, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V` |

## Dynamic Analysis Findings

Dynamic analysis was skipped. To enable it, start the ghera27 emulator (check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.
