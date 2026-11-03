# diva-beta report

| Component | Type | Issue | CWE | Confidence | Evidence |
|---|---|---|---|---|---|
| jakhar.aseem.diva.APICredsActivity | activity | exported-no-permission | CWE-926 | medium |  |
| jakhar.aseem.diva.APICredsActivity | activity | implicit-intent | CWE-927 | medium |  |
| jakhar.aseem.diva.APICreds2Activity | activity | exported-no-permission | CWE-926 | medium |  |
| jakhar.aseem.diva.APICreds2Activity | activity | implicit-intent | CWE-927 | medium |  |
| jakhar.aseem.diva.NotesProvider | provider | exported-no-permission | CWE-926 | high | `android:exported="true" with no android:permission, android:readPermission or android:writePermission: any app can query and modify it` |
| (application) | application | cleartext-http | CWE-319 | low |  |
| (application) | application | default-task-affinity | CWE-1021 | low | `<application> has no android:taskAffinity and no activity sets one; launcher jakhar.aseem.diva.MainActivity uses the default affinity (the package name jakhar.aseem.diva)` |
| jakhar.aseem.diva.InputValidation2URISchemeActivity | class | js_enabled | CWE-749 | medium | `invoke-virtual {v0, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V` |
| jakhar.aseem.diva.InsecureDataStorage2Activity | class | sql_injection_raw | CWE-89 | high | `invoke-virtual {v3, v4}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V` |
| jakhar.aseem.diva.InsecureDataStorage4Activity | class | external_storage_io | CWE-922 | low | `invoke-direct {v1, v4}, Ljava/io/FileWriter;-><init>(Ljava/io/File;)V [hardcoded path "/.uinfo.txt" with no sensitive word]` |
| jakhar.aseem.diva.SQLInjectionActivity | class | sql_injection_raw | CWE-89 | high | `invoke-virtual {v4, v5, v6}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;` |

## Dynamic Analysis Findings

Dynamic analysis was skipped. To enable it, start the ghera27 emulator (check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.
