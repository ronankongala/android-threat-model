# com.drip_51 report

| Component | Type | Issue | CWE | Confidence | Evidence |
|---|---|---|---|---|---|
| com.drip.MainActivity | activity | task-affinity-hijack | CWE-1021 | medium | `android:launchMode="singleTask"` |
| com.dieam.reactnativepushnotification.modules.RNPushNotificationActions | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {p1, p2}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V` |
| com.facebook.react.modules.systeminfo.AndroidInfoModule | class | unique_ids | CWE-359 | high | `invoke-static {v0, v1}, Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;` |
| me.leolin.shortcutbadger.impl.SonyHomeBadger | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {p0, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V` |
| me.leolin.shortcutbadger.impl.VivoHomeBadger | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {p1, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V` |

## Dynamic Analysis Findings

Dynamic analysis was skipped. To enable it, start the ghera27 emulator (check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.
