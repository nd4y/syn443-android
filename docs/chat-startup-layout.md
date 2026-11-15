# Chat startup layout correction

Main `f3b75609a6ac98e9c42114879653ede56b8b5520`, Actions run
`43684857143`, API 35, failed the original
`ChatUiTest.supportChatHasVisibleTitleAndConnectionStatus`. The Android crash
buffer identifies a main-thread `IllegalArgumentException` from Compose
`MeasureAndLayoutDelegate` during `AndroidComposeView.dispatchDraw`:
`performMeasureAndLayout called during measure layout`. This was an application
process crash, not the earlier Settings-window focus observer failure.

The former activity attached its Compose root only after asynchronous cache
preparation returned. This correction installs the root synchronously in
`onCreate`, renders a preparation state and starts chat operations only after
the existing owned-file cleanup finishes. Cleanup cannot race a new attachment
operation. Encryption, account generation, queue limits and authorization do
not change.

The original UI assertion remains mandatory. Additional mandatory cases perform
five activity recreations and five stop/resume transitions, checking the visible
title, status and installed root after each transition. No retries, caught
rendering exceptions, skipped outcomes or test-clock shortcuts are introduced.

This removes a late-root startup race boundary; the available stack does not
prove that boundary was the complete cause of the Compose reentrant traversal.
Permanent root-cause closure is not claimed. Exact-head Actions results and
verified Xperia USB/Wi-Fi acceptance are required before release. Version 76
remains unaccepted until those checks complete; the installed version 75 is a
separate accepted checkpoint. LTE and battery/endurance paths remain excluded.
