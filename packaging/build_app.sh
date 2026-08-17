#!/bin/bash
# Builds ObscuraLux Unwarez.app from the SwiftPM package at the repo
# root. The app bundles unwarez-cli (Contents/Resources/unwarez-cli) so
# LaunchAgent-scheduled scans can run without the GUI app open.
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGING_DIR="$REPO_ROOT/packaging"
BUILD_DIR="$REPO_ROOT/build"
BUNDLE_NAME="ObscuraLux Unwarez.app"
GUI_PRODUCT="ObscuraLuxUnwarezGUI"
CLI_PRODUCT="unwarez-cli"

echo "[1/6] Bumping version..."
# Info.plist is the single source of truth for the version - build_dmg.sh
# reads it back out rather than hardcoding its own copy, so the two can
# never drift. Every build_app.sh run bumps the patch number, so any two
# builds are always distinguishable by version alone.
PLIST="$PACKAGING_DIR/Info.plist"
CURRENT_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$PLIST")
IFS='.' read -r VMAJOR VMINOR VPATCH <<< "$CURRENT_VERSION"
NEW_VERSION="${VMAJOR}.${VMINOR}.$((VPATCH + 1))"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $NEW_VERSION" "$PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $NEW_VERSION" "$PLIST"
echo "  $CURRENT_VERSION -> $NEW_VERSION"

echo "[2/6] Checking for Swift toolchain..."
if ! command -v swift >/dev/null 2>&1; then
    echo "swift not found. Install Xcode Command Line Tools first:"
    echo "  xcode-select --install"
    exit 1
fi

echo "[3/6] Cleaning previous build..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/$BUNDLE_NAME/Contents/MacOS"
mkdir -p "$BUILD_DIR/$BUNDLE_NAME/Contents/Resources"

# Deployment target is 12.0, matching Info.plist's LSMinimumSystemVersion
# (see Package.swift's `platforms:` and docs/DEVELOPER_NOTES.md for why).
#
# `swift build --arch arm64 --arch x86_64` (a single invocation producing
# a universal binary) needs XCBuild, which isn't part of a bare Command
# Line Tools install - only full Xcode ships it. Command Line Tools *can*
# do a single-arch release build per architecture, so this does the same
# two-pass-plus-lipo dance the previous raw-swiftc version of this script
# used, just via `swift build` instead.
echo "[4/6] Building both architectures (arm64 + x86_64)..."
cd "$REPO_ROOT"
for arch in arm64 x86_64; do
    swift build -c release --arch "$arch" --product "$GUI_PRODUCT"
    swift build -c release --arch "$arch" --product "$CLI_PRODUCT"
done

ARM_DIR=".build/arm64-apple-macosx/release"
X86_DIR=".build/x86_64-apple-macosx/release"

lipo -create -output "$BUILD_DIR/$BUNDLE_NAME/Contents/MacOS/$GUI_PRODUCT" \
    "$ARM_DIR/$GUI_PRODUCT" "$X86_DIR/$GUI_PRODUCT"
lipo -create -output "$BUILD_DIR/$BUNDLE_NAME/Contents/Resources/$CLI_PRODUCT" \
    "$ARM_DIR/$CLI_PRODUCT" "$X86_DIR/$CLI_PRODUCT"
chmod +x "$BUILD_DIR/$BUNDLE_NAME/Contents/MacOS/$GUI_PRODUCT" \
    "$BUILD_DIR/$BUNDLE_NAME/Contents/Resources/$CLI_PRODUCT"

echo "[5/6] Assembling app bundle..."
cp "$PACKAGING_DIR/Info.plist" "$BUILD_DIR/$BUNDLE_NAME/Contents/Info.plist"
cp "$PACKAGING_DIR/AppIcon.icns" "$BUILD_DIR/$BUNDLE_NAME/Contents/Resources/AppIcon.icns"

# UnwarezCore's SwiftPM resource bundle (ThreatIntel.json +
# ReleaseSealDatabase.json) - identical content per architecture, so
# either build directory's copy is fine.
#
# Goes in Contents/Resources/, the correct/standard location for a real
# .app - NOT the bundle root. SwiftPM's generated Bundle.module accessor
# looks relative to Bundle.main.bundleURL (the bundle root) with a
# hardcoded-at-build-time fallback into this machine's own .build/
# directory, both wrong for a packaged app on any other machine - and
# codesign refuses to seal anything placed at the bundle root anyway
# ("unsealed contents present in the bundle root"). UnwarezPaths.
# bundledResourceURL() is what actually finds this at runtime; it checks
# Contents/Resources/ first and only falls back to Bundle.module for
# swift run/test dev contexts. See its doc comment for the full story.
RESOURCE_BUNDLE=$(find "$ARM_DIR" -maxdepth 1 -iname "*_UnwarezCore.bundle" | head -1)
if [ -z "$RESOURCE_BUNDLE" ]; then
    echo "Could not find UnwarezCore's resource bundle in $ARM_DIR" >&2
    exit 1
fi
cp -R "$RESOURCE_BUNDLE" "$BUILD_DIR/$BUNDLE_NAME/Contents/Resources/"

echo "[6/6] Ad-hoc code signing..."
# Apple Silicon refuses to run ANY compiled Mach-O executable with zero
# signature at all, regardless of Gatekeeper/quarantine status - a
# different, stricter check than the "unidentified developer" warning.
# Ad-hoc signing (no paid account needed) satisfies it.
codesign --force --deep --sign - "$BUILD_DIR/$BUNDLE_NAME"

echo ""
echo "Built: $BUILD_DIR/$BUNDLE_NAME"
echo "Run it with: open \"$BUILD_DIR/$BUNDLE_NAME\""
