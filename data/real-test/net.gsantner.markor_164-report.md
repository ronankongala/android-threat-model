# net.gsantner.markor_164 report

| Component | Type | Issue | CWE | Confidence | Evidence |
|---|---|---|---|---|---|
| net.gsantner.markor.activity.SettingsActivity | activity | exported-no-permission | CWE-926 | high |  |
| other.writeily.widget.WrWidgetConfigure | activity | exported-no-permission | CWE-926 | high |  |
| net.gsantner.markor.activity.DocumentActivity | activity | exported-no-permission | CWE-926 | high |  |
| net.gsantner.markor.AliasDocumentProcessText | activity-alias | exported-no-permission | CWE-926 | high |  |
| other.writeily.widget.WrMarkorWidgetProvider | receiver | exported-no-permission | CWE-926 | high |  |
| net.gsantner.markor.widget.TodoWidgetProvider | receiver | exported-no-permission | CWE-926 | high |  |
| (application) | application | default-task-affinity | CWE-1021 | low | `<application> has no android:taskAffinity and no activity sets one; launcher net.gsantner.markor.activity.MainActivity uses the default affinity (the package name net.gsantner.markor)` |
| (application) | application | certificate_pinning_missing | CWE-295 | high | `no network security config, usesCleartextTraffic ="true"; network call invoke-virtual {p0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;` |
| net.gsantner.markor.activity.DocumentEditAndViewFragment | class | js_enabled | CWE-749 | medium | `invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V` |
| net.gsantner.markor.activity.DocumentEditAndViewFragment | class | webview_file_access | CWE-829 | medium | `invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V` |
| net.gsantner.opoc.util.GsContextUtils | class | directory_traversal | CWE-22 | medium | `invoke-direct {v1, v3, p0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V` |
| net.gsantner.opoc.util.GsContextUtils | class | pending_intent_mutable | CWE-927 | high | `invoke-static {p1, v1, v0, p2}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent; [flags 0x10000000: neither FLAG_IMMUTABLE nor FLAG_MUTABLE; required for apps targeting API 31+ (targetSdkVersion 35), a mutable PendingIntent lets the receiving app fill in its Intent]` |
| net.gsantner.markor.frontend.AttachLinkOrFileDialog$$ExternalSyntheticLambda10 | class | taint-flow | CWE-22 | low | `source L133: invoke-virtual {p2}, Landroid/widget/EditText;->getText()Landroid/text/Editable; \| sink L108: invoke-direct {v0, p1}, Ljava/io/File;-><init>(Ljava/lang/String;)V [validated on the path: in a caller]` |

## Dynamic Analysis Findings

Dynamic analysis was skipped. To enable it, start the ghera27 emulator (check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.
