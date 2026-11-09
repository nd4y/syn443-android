# Android UI defaults

SYN443 starts in a deterministic Material 3 dark palette, independently of the system
night mode. The root Surface paints the complete app background; text, controls,
dialogs and future screens inherit the same theme. The platform launch/window theme
is dark too, including system-bar icon contrast. Do not silently switch to a light
palette or dynamic wallpaper colors. Theme defaults never modify the Android system setting.

Respect safe drawing insets and cutouts; provide scrolling on small viewports. CI
emulators explicitly use light system mode and check rendered dark-background luminance,
title contrast (at least 4.5:1), bounds below system bars and interactive controls.
Physical validation is recorded privately; raw screenshots and device logs stay outside GitHub.

The home screen places the current VPN state and one primary action above account and
support actions. Connect requires a known status. Stop stays available while the user
intends the VPN to run, including recovery and permission waits. A rejected Connect does
not launch the system permission prompt. The last connection state is marked unavailable
if the controller cannot provide a fresh status.

The Routes and diagnostics section contains policy, route, NetBird, system VPN, resource
and engine details. It starts collapsed. The synthetic route model has a separate
collapsed developer section in debug builds. The emulator evidence gate requires both
home layout and primary action tests on APIs 29, 35 and 37. Startup transitions,
the complete accessibility matrix and physical UI-01/AC81 acceptance remain partial.
