#!/bin/bash
# Build "Draytek VPN Custom Route.app" using only the Command Line Tools (no Xcode needed).
# Icon: run `swift make-icon.swift AppIcon.iconset && iconutil -c icns AppIcon.iconset` to regenerate AppIcon.icns.
set -e
cd "$(dirname "$0")"
APP="Draytek VPN Custom Route.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -parse-as-library -O -o "$APP/Contents/MacOS/DraytekVPNCustomRoute" main.swift
cp Info.plist "$APP/Contents/Info.plist"
cp AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
codesign --sign - --force "$APP"
echo "Built: $(pwd)/$APP"
