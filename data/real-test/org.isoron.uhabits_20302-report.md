# org.isoron.uhabits_20302 report

| Component | Type | Issue | CWE | Confidence | Evidence |
|---|---|---|---|---|---|
| org.isoron.uhabits.activities.habits.edit.EditHabitActivity | activity | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.activities.habits.list.ListHabitsActivity | activity | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.widgets.activities.HabitPickerDialog | activity | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.widgets.activities.BooleanHabitPickerDialog | activity | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.widgets.activities.NumericalHabitPickerDialog | activity | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.notifications.SnoozeDelayPickerActivity | activity | task-affinity-hijack | CWE-1021 | medium | `android:launchMode="singleInstance"` |
| org.isoron.uhabits.automation.EditSettingActivity | activity | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.widgets.CheckmarkWidgetProvider | receiver | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.widgets.HistoryWidgetProvider | receiver | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.widgets.ScoreWidgetProvider | receiver | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.widgets.StreakWidgetProvider | receiver | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.widgets.FrequencyWidgetProvider | receiver | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.widgets.TargetWidgetProvider | receiver | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.receivers.ReminderReceiver | receiver | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.automation.FireSettingReceiver | receiver | exported-no-permission | CWE-926 | high |  |
| org.isoron.uhabits.receivers.ReminderController | class | implicit_broadcast | CWE-927 | medium | `invoke-virtual {p2, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V` |

## Dynamic Analysis Findings

Dynamic analysis was skipped. To enable it, start the ghera27 emulator (check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.
