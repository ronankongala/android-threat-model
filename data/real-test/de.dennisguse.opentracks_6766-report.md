# de.dennisguse.opentracks_6766 report

| Component | Type | Issue | CWE | Confidence | Evidence |
|---|---|---|---|---|---|
| de.dennisguse.opentracks.publicapi.StartRecording | activity | exported-no-permission | CWE-926 | high |  |
| de.dennisguse.opentracks.publicapi.StopRecording | activity | exported-no-permission | CWE-926 | high |  |
| de.dennisguse.opentracks.publicapi.CreateMarker | activity | exported-no-permission | CWE-926 | high |  |
| de.dennisguse.opentracks.HealthConnectPermissionsRationaleActivity | activity | exported-no-permission | CWE-926 | high |  |
| de.dennisguse.opentracks.io.file.importer.ImportActivity | activity | exported-no-permission | CWE-926 | high |  |
| de.dennisguse.opentracks.publicapi.ShowMarkerActivity | activity | exported-no-permission | CWE-926 | high |  |
| de.dennisguse.opentracks.publicapi.CreateMarkerActivity | activity | exported-no-permission | CWE-926 | high |  |
| de.dennisguse.opentracks.ShowErrorActivity | activity | task-affinity-hijack | CWE-1021 | medium | `android:launchMode="singleInstance"` |
| androidx.health.platform.client.impl.sdkservice.HealthDataSdkService | service | exported-no-permission | CWE-926 | high |  |
| (application) | application | default-task-affinity | CWE-1021 | low | `<application> has no android:taskAffinity and no activity sets one; launcher de.dennisguse.opentracks.introduction.IntroductionActivity uses the default affinity (the package name de.dennisguse.opentracks)` |
| de.dennisguse.opentracks.data.CustomContentProvider | class | sql_injection_raw | CWE-89 | medium | `invoke-virtual {p0, p1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V` |
| de.dennisguse.opentracks.ShowErrorActivity | class | taint-flow | CWE-927 | high | `source L75: invoke-virtual {v1}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence; \| sink L89: invoke-virtual {p0, v0}, Lde/dennisguse/opentracks/ShowErrorActivity;->startActivity(Landroid/content/Intent;)V` |

## Dynamic Analysis Findings

Dynamic analysis was skipped. To enable it, start the ghera27 emulator (check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.
