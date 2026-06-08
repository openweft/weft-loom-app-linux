package main

import _ "embed"

// iconData is the colour brand mark (weft-A-weave) — used for the .icns /
// DMG and as the tray icon on Linux/Windows.
//
//go:embed assets/icon.png
var iconData []byte

// iconTemplateData is a black+alpha template of the mark. On macOS the tray
// uses this so the menu bar auto-tints it for light/dark; other platforms
// fall back to iconData.
//
//go:embed assets/icon-template.png
var iconTemplateData []byte
