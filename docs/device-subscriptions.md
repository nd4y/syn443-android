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
never forward credentials or conditional headers after crossing origins.

The response is bounded to 10 MiB after decompression. The device sends the
provider bytes with a DPoP proof covering the full job/lease frame. It neither
imports the provider configuration into the running engine nor publishes it.
The source worker normalizes profiles and the regular signed assignment flow
applies approved selections. Conditional server cache reuse, provider quota
metadata, other network contexts and live provider acceptance remain open.
