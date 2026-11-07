# Device subscription fetch over Wi-Fi

An authorized policy response may advertise device fetch. The login worker
remembers that capability for the current device session. While the VPN is On,
it may claim one addressed subscription job on the same validated physical
Wi-Fi route used for the download and result upload. It uses the existing worker
and a bounded poll interval. Stop, logout or a route change invalidates the work.

The device uses TLS hostname verification and the source's authorized private
prefixes and CA if present. It checks DNS addresses before each dial. Loopback,
link-local and metadata addresses and configured control-plane origins are
unavailable to subscription fetch. Redirects need an allowed HTTPS origin and
never forward credentials after crossing origins. Conditional headers are
confined to the original URL, even when a redirect stays on the same origin.

The response is bounded to 10 MiB after decompression. The device sends the
provider bytes with a DPoP proof covering the full job/lease frame. It neither
imports the provider configuration into the running engine nor publishes it.
The source worker normalizes profiles and the regular signed assignment flow
applies approved selections. When the server advertises support, a version 2
lease can carry validators for an existing working snapshot. A provider 304
returns metadata without a profile body. Quota and fixed provider error statuses
also travel inside the proof; provider error bodies and headers are never sent.
Older servers retain the original full-body exchange. Physical acceptance and
device fetch in other network contexts remain open.
