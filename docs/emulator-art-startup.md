# Actual ART heap in disposable CI

The API29 job in run43737241443 failed when Android `system_server` exhausted
its actual16MiB growth limit in `ConfigUpdateInstallReceiver`, although the
heap properties reported512MiB. The OS failure interrupted Binder tests and
instrumentation. API35/37 passed. The failed run remains evidence.

Android10 [AndroidRuntime.cpp](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-10.0.0_r47/core/jni/AndroidRuntime.cpp)
reads heap flags when starting the VM and defaults `dalvik.vm.heapsize` to16m.
Property readback does not prove an existing VM's heap. An early startup before
the final emulator properties is a hypothesis, not a confirmed permanent cause.

Before APK installation, `prepare_emulator_art.py` restarts the framework once
on API29 only. It requires GitHub Actions, the exact `syn443-ci` AVD name,
emulator serial/hardware, a debuggable image, representative heap properties
and neither application nor test APK installed. It rechecks ownership after
adbd obtains root, observes the old system_server exit and a new ready process,
and bounds the wait. Lost acknowledgements cannot replay stop/start. A failed
stop observation still dispatches start once. It never resets userdata or
changes application memory limits.

Host fixtures cover owner/device/installed-app fences, root failure, lost
acknowledgements, stuck/unchanged processes and readiness deadlines. A new
instrumented `RuntimeHeapTest` checks the running application's actual
`Runtime.maxMemory()` independently of properties. All241 Android outcomes,
including every existing media/storage/process/OS case, are mandatory without
skips on API29/35/37. API35/37 never execute the framework restart.

Acceptance requires the exact-source full Actions matrix. This fixture does
not establish physical memory, cellular, battery or endurance acceptance.
