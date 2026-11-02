# app-api27-debug report

| Component | Type | Issue | CWE | Confidence | Evidence |
|---|---|---|---|---|---|
| edu.ksu.cs.benign.EmailBroadcastRecv | class | no_validity_check | CWE-925 | medium | `invoke-virtual {p1, v2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V` |
| edu.ksu.cs.benign.MainActivity$1 | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {v1, v0}, Ledu/ksu/cs/benign/MainActivity;->sendBroadcast(Landroid/content/Intent;)V` |
| edu.ksu.cs.benign.EmailBroadcastRecv | class | taint-flow | CWE-926 | high | `source L34: invoke-virtual {p2, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String; \| sink L58: invoke-virtual {p1, v2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V` |

## Dynamic Analysis Findings

Dynamic analysis was skipped. To enable it, start the ghera27 emulator (check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.
