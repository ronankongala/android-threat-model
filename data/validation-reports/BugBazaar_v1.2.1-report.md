# BugBazaar_v1.2.1 report

| Component | Type | Issue | CWE | Confidence | Evidence |
|---|---|---|---|---|---|
| com.BugBazaar.ExternalAuthLogin | activity | exported-no-permission | CWE-926 | high |  |
| com.BugBazaar.ExternalAuthLogin | activity | task-affinity-hijack | CWE-1021 | medium | `android:launchMode="singleTask"` |
| com.BugBazaar.ui.ContactsPack.ReferUs | activity | exported-no-permission | CWE-926 | high |  |
| com.BugBazaar.ui.MyProfile | activity | exported-no-permission | CWE-926 | high |  |
| com.BugBazaar.ui.TermsAndConditionsActivity | activity | exported-no-permission | CWE-926 | high |  |
| com.BugBazaar.ui.Contact_us | activity | exported-no-permission | CWE-926 | high |  |
| com.BugBazaar.ui.Signin | activity | exported-no-permission | CWE-926 | high |  |
| com.BugBazaar.ui.Deeplink | activity | exported-no-permission | CWE-926 | high |  |
| com.razorpay.CheckoutActivity | activity | exported-no-permission | CWE-926 | high |  |
| com.BugBazaar.ui.components.SMSService | service | exported-no-permission | CWE-926 | high |  |
| com.BugBazaar.ui.components.CustomBR | receiver | exported-no-permission | CWE-926 | high |  |
| com.razorpay.RzpTokenReceiver | receiver | exported-no-permission | CWE-926 | high |  |
| com.BugBazaar.provider.UserProfileProvider | provider | exported-no-permission | CWE-926 | low | `android:exported="true" with android:readPermission but no android:writePermission` |
| com.BugBazaar.ui.addresses.AddressContentProvider | provider | exported-no-permission | CWE-926 | high | `android:exported="true" with no android:permission, android:readPermission or android:writePermission: any app can query and modify it` |
| (application) | application | cleartext-http | CWE-319 | high |  |
| (application) | application | default-task-affinity | CWE-1021 | low | `<application> has no android:taskAffinity and no activity sets one; launcher com.BugBazaar.ui.SplashActivity uses the default affinity (the package name com.BugBazaar)` |
| com.BugBazaar.ui.Contact_us | class | js_enabled | CWE-749 | medium | `invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V` |
| com.BugBazaar.ui.Contact_us | class | webview_file_access | CWE-829 | medium | `invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V` |
| com.BugBazaar.ui.Contact_us | class | webview_file_url_access | CWE-830 | high | `invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V` |
| com.BugBazaar.ui.ContactsPack.ReferUs | class | fragment_injection | CWE-470 | medium | `invoke-static {p0, p1, v2}, Landroidx/fragment/app/Fragment;->instantiate(Landroid/content/Context;Ljava/lang/String;Landroid/os/Bundle;)Landroidx/fragment/app/Fragment;` |
| com.BugBazaar.ui.Deeplink | class | js_enabled | CWE-749 | medium | `invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V` |
| com.BugBazaar.ui.Deeplink | class | webview_file_url_access | CWE-830 | high | `invoke-virtual {p1, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V` |
| com.BugBazaar.ui.TermsAndConditionsActivity | class | js_enabled | CWE-749 | medium | `invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V` |
| com.BugBazaar.ui.TermsAndConditionsActivity | class | webview_file_url_access | CWE-830 | high | `invoke-virtual {p1, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V` |
| com.BugBazaar.ui.addresses.AddressDatabaseHelper | class | sql_injection_raw | CWE-89 | high | `invoke-virtual {v1, p1, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;` |
| com.BugBazaar.ui.cart.NotificationHelper | class | pending_intent_empty | CWE-927 | high | `invoke-static {p0, v2, v0, v1}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;` |
| com.BugBazaar.ui.components.CustomBR | class | no_validity_check | CWE-925 | medium | `invoke-virtual {p1, p2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V` |
| com.BugBazaar.ui.myorders.OrderHistoryDatabaseHelper | class | sql_injection_raw | CWE-89 | high | `invoke-virtual {v1, p1, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;` |
| com.BugBazaar.utils.DeviceDetails | class | unique_ids | CWE-359 | high | `invoke-static {p0, v0}, Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;` |
| com.BugBazaar.utils.NotificationUtils | class | pending_intent_empty | CWE-927 | high | `invoke-static {p0, v2, v0, v1}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;` |
| com.BugBazaar.utils.checkWorker | class | dynamic_code_load | CWE-494 | high | `invoke-direct {v0, p1, v1, v4, v2}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V` |
| com.bumptech.glide.manager.DefaultConnectivityMonitor | class | dynamic_receiver_no_permission | CWE-926 | high | `invoke-virtual {v0, v1, v2}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent; [no broadcastPermission argument: any app can send this receiver a broadcast]` |
| com.evernote.android.job.JobStorage$JobOpenHelper | class | sql_injection_raw | CWE-89 | medium | `invoke-virtual {p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V` |
| com.evernote.android.job.util.Device | class | dynamic_receiver_no_permission | CWE-926 | high | `invoke-virtual {p0, v1, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent; [no broadcastPermission argument: any app can send this receiver a broadcast]` |
| com.evernote.android.job.v21.TransientBundleCompat | class | pending_intent_mutable | CWE-927 | high | `invoke-static {p0, p1, p2, v0}, Landroid/app/PendingIntent;->getService(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent; [flags 0x20000000: neither FLAG_IMMUTABLE nor FLAG_MUTABLE; required for apps targeting API 31+ (targetSdkVersion 32), a mutable PendingIntent lets the receiving app fill in its Intent]` |
| com.razorpay.BaseUtils | class | js_enabled | CWE-749 | medium | `invoke-virtual {p0, v0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V` |
| com.razorpay.BaseUtils | class | unique_ids | CWE-359 | high | `invoke-static {p0, v0}, Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;` |
| com.razorpay.CheckoutPresenterImpl | class | dynamic_receiver_no_permission | CWE-926 | high | `invoke-virtual {v1, v2, v0}, Landroid/app/Activity;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent; [no broadcastPermission argument: any app can send this receiver a broadcast]` |
| com.razorpay.PrimaryWebViewClient | class | webview_override_allows_all | CWE-829 | low | `.method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z` |
| com.razorpay.SecondaryWebViewClient | class | webview_override_allows_all | CWE-829 | low | `.method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z` |
| com.razorpay.SmsReceiver | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {p1, v2}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V` |
| com.squareup.picasso.Dispatcher$NetworkBroadcastReceiver | class | dynamic_receiver_no_permission | CWE-926 | high | `invoke-virtual {v1, p0, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent; [no broadcastPermission argument: any app can send this receiver a broadcast]` |
| com.BugBazaar.ui.components.SMSService | class | taint-flow | CWE-200 | high | `source L32: invoke-virtual {p1, p2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String; \| sink L55: invoke-virtual/range {v0 .. v5}, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V` |
| com.razorpay.CheckoutPresenterImpl | class | taint-flow | CWE-927 | high | `source L2184: invoke-virtual {p3}, Landroid/content/Intent;->getData()Landroid/net/Uri; \| sink L2266: invoke-virtual {p1, p2}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V` |

## Dynamic Analysis Findings

Dynamic analysis was skipped. To enable it, start the ghera27 emulator (check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.
