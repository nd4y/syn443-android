# Manual enrollment and signed health component acceptance

Accepted Android source: `fb18f759fd0aa5df937a213a05aa2af76b96b829`, versionCode29,
version0.9.1. All mandatory jobs in [Actions41372861986](https://github.com/nd4y/syn443-android/actions/runs/41372861986)
passed, including API29/35/37. The APK archive digest was independently verified:
`6811dfcd68a1004cd57a618fba8c88fa17f550a92d7d0c5877a5f480cd64fab0`.
Archive inventory/version, private development signing and on-device APK SHA256
were verified separately. This is a component snapshot, not a completed M2/M3
milestone or a production signing/release acceptance.

Actual Xperia USB/Wi-Fi acceptance used Actions-built control/identity API and
independent publisher from source`f392cd47f380fa405b74ddf8d03b7c8b811e0024`
([server Actions](https://github.com/nd4y/syn443-control-plane/actions/runs/41367624189)),
role-restricted PostgreSQL, TLS over owned USB forwarding and a synthetic issuer.
It exercised local signed-link preview, explicit enrollment, a UI pairing code
matched to the actual server claim, explicit admin approval, ordinary key-bound
session/policy delivery and actual signed-config VPN activation. It does not prove
real Keycloak browser login/MFA or physical camera/QR capture.

The Wi-Fi allowed ordinary HTTPS but the default gstatic endpoint timed out.
A separately verified reachable HTTPS204 target exposed and then verified the
fix: managed ongoing health must use every required HTTPS target from the
currently authorized policy for the actual running engine. A missing/expired or
wrong-engine managed view has no default-URL fallback, and completion repeats the
authority check. API/TUN HTTPS, native crash/replacement, native hang/replacement
and Wi-Fi loss/rebound all passed after the fix. Mobile data stayed isolated;
LTE was not tested. OS validation and actual HTTPS results are separate facts.

After logout the real identity API retired the test device. The original operator
configuration remained byte-identical and the original SDK identity fingerprints
matched the fresh encrypted checkpoint. The restored original profile passed real
HTTPS, direct-underlay NetBird management/signal and a required private-peer reply;
this does not mean every peer used P2P. Original bootstrap/OS/mobile/Wi-Fi settings
and Off/native-retired state were verified. The initially absent test APK, owned
forwards, synthetic runtime processes and labelled SQL container were removed.
The tested main APK remains installed. All private receipts, keys, device/config
material and raw diagnostics remain outside public repositories/artifacts.

Managed overlay credential delivery/retirement, complete administration/editor,
source/compiler publication and the full protocol matrix remain open. Natural
Doze, unplugged battery/endurance, LTE and production deployment are separate gates.
