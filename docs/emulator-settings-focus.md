# Disposable emulator Settings ownership

The API37 documentation run43679315846 stopped at the ordinary VPN Settings
navigation gate, with a framework ANR dialog and no owned settings row. It did
not complete235 outcomes and remains failed evidence. The SYN443 runtime was
Online with actual route checks; that alone does not accept the lifecycle case.
The dialog's process owner was not captured, so this is not a proved app RCA.

Source review found a fixture observation defect: it searched `dumpsys window
windows` for current focus. Modern AOSP prints that field in
[DisplayContent.dump](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/wm/DisplayContent.java),
which the `displays` subcommand selects in
[WindowManagerService](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/wm/WindowManagerService.java).
The helper now queries display state with a bounded read. Only one exact current
focus naming the Settings ANR permits the existing single activity restart.
Absent, oversized, ambiguous, previous or foreign focus is rejected. No generic
error-dialog button is pressed; no app crash is dismissed. The physical-device
and protected-keyguard guards remain unchanged.

Required acceptance retains all235 cases on API29/35/37 and adds positive and
negative fixture tests. This changes only the host-side observer and documents;
the installed v75 application/native source is unchanged. The failed run is
not converted to a pass by this correction or by synthetic ownership tests.
