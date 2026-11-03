# InsecureShop report

| Component | Type | Issue | CWE | Confidence | Evidence |
|---|---|---|---|---|---|
| com.insecureshop.ChooserActivity | activity | exported-no-permission | CWE-926 | medium |  |
| com.insecureshop.ChooserActivity | activity | implicit-intent | CWE-927 | low |  |
| com.insecureshop.AboutUsActivity | activity | exported-no-permission | CWE-926 | high |  |
| com.insecureshop.WebViewActivity | activity | exported-no-permission | CWE-926 | medium |  |
| com.insecureshop.WebViewActivity | activity | implicit-intent | CWE-927 | low |  |
| com.insecureshop.WebView2Activity | activity | exported-no-permission | CWE-926 | medium |  |
| com.insecureshop.WebView2Activity | activity | implicit-intent | CWE-927 | medium |  |
| com.insecureshop.ResultActivity | activity | exported-no-permission | CWE-926 | high |  |
| net.gotev.uploadservice.UploadService | service | exported-no-permission | CWE-926 | high |  |
| com.insecureshop.contentProvider.InsecureShopProvider | provider | weak-permission-protection | CWE-926 | medium | `android:readPermission="com.insecureshop.permission.READ" is declared with protectionLevel normal: normal permissions are granted automatically to any app that requests them` |
| (application) | application | default-task-affinity | CWE-1021 | low | `<application> has no android:taskAffinity and no activity sets one; launcher com.insecureshop.ProductListActivity uses the default affinity (the package name com.insecureshop)` |
| (application) | application | certificate_pinning_missing | CWE-295 | high | `no network security config, usesCleartextTraffic ="true"; network call invoke-virtual {p1}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;` |
| com.bumptech.glide.manager.DefaultConnectivityMonitor | class | dynamic_receiver_no_permission | CWE-926 | high | `invoke-virtual {v0, v1, v2}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent; [no broadcastPermission argument: any app can send this receiver a broadcast]` |
| com.insecureshop.AboutUsActivity | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {p0, v2}, Lcom/insecureshop/AboutUsActivity;->sendBroadcast(Landroid/content/Intent;)V` |
| com.insecureshop.ChooserActivity | class | directory_traversal | CWE-22 | medium | `invoke-direct {v1, v2}, Ljava/io/File;-><init>(Ljava/lang/String;)V` |
| com.insecureshop.CustomReceiver | class | no_validity_check | CWE-925 | medium | `invoke-virtual {p1, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V` |
| com.insecureshop.PrivateActivity | class | js_enabled | CWE-749 | medium | `invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V` |
| com.insecureshop.PrivateActivity | class | webview_file_url_access | CWE-830 | high | `invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V` |
| com.insecureshop.ProductAdapter$onBindViewHolder$3 | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {v1, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V` |
| com.insecureshop.ProductListActivity | class | dynamic_receiver_no_permission | CWE-926 | high | `invoke-virtual {p0, v1, v0}, Lcom/insecureshop/ProductListActivity;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent; [no broadcastPermission argument: any app can send this receiver a broadcast]` |
| com.insecureshop.WebView2Activity | class | js_enabled | CWE-749 | medium | `invoke-virtual {v2, v4}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V` |
| com.insecureshop.WebView2Activity | class | webview_file_url_access | CWE-830 | high | `invoke-virtual {v2, v4}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V` |
| com.insecureshop.WebViewActivity | class | js_enabled | CWE-749 | medium | `invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V` |
| com.insecureshop.WebViewActivity | class | webview_file_url_access | CWE-830 | high | `invoke-virtual {v1, v3}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V` |
| com.insecureshop.broadcast.ProductDetailBroadCast | class | no_validity_check | CWE-925 | medium | `invoke-virtual {p1, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V` |
| com.insecureshop.util.CustomWebViewClient | class | webview_ssl_proceed | CWE-295 | medium | `invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V` |
| net.gotev.uploadservice.UploadNotificationConfig | class | pending_intent_empty | CWE-927 | high | `invoke-static {p1, v0, v2, v1}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;` |
| net.gotev.uploadservice.UploadServiceBroadcastReceiver | class | dynamic_receiver_no_permission | CWE-926 | high | `invoke-virtual {p1, p0, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent; [no broadcastPermission argument: any app can send this receiver a broadcast]` |
| net.gotev.uploadservice.UploadTask | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {v0, v1}, Lnet/gotev/uploadservice/UploadService;->sendBroadcast(Landroid/content/Intent;)V` |

## Dynamic Analysis Findings

Dynamic analysis was skipped. To enable it, start the ghera27 emulator (check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.
