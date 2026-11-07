# Bounded pending-credential retry and changed-authority recovery

The waiting-credential and sealed-key interrupted-registration paths passed all
eight mandatory jobs at`3c318aaf8523ebd9b2211d5d61ad81d89b92518c`,
[Actions41470728908](https://github.com/nd4y/syn443-android/actions/runs/41470728908),
including API29/35/37. This is compiled/emulator evidence, not actual Cloud or
final physical-device acceptance. Full M2/M3 scope remains incomplete.

The new follow-up keeps pending overlay delivery independent of the long policy
refresh interval. The existing desired-On/eligible-network supervisor path uses
the bounded generation/backoff admission, refreshes an expiring session if needed
and retries the same durable credential operation without fetching policy again.
There is no additional timer or native restart-budget charge. Logout prevents
admission, and current scope/epoch/queue fences still reject late work. Ordinary
forced policy refresh retains priority. The backoff starts at5 seconds, increases
up to60 seconds and admits at most6 attempts in a5-minute rolling window.

An ENROLLING identity whose same-reference grant loses security-epoch authority
also erases that grant before a sealed-existing-key probe. It cannot borrow the
old secret, fetch it under new authority or acknowledge registration without the
current private native proof. A different device key/identity still fails before
erasure. This transition does not remove or regenerate SDK keys. Native recovery
continues to require an initialized sealed manifest and matching key evidence.

Two required platform regressions and the179-case minimum cover these new paths.
The retry case verifies the same operation, no extra policy GET, no duplicate
fetch once material is usable and no admission after logout. The epoch case checks
foreign-key denial before erasure, durable key/cipher erasure, no secret request
and acknowledgment only after current private proof. Their compiled acceptance
is pending the next Actions run. Configured issuer/materializer, actual Cloud,
complete administration and final restored USB Xperia Wi-Fi acceptance remain
open; LTE/Pixel are excluded from current testing.
