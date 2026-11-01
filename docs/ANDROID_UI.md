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

This is the diagnostic prototype UI. The full application screens, startup transitions,
accessibility matrix and complete UI-01/AC81 acceptance remain partial until implemented.
