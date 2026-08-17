#!/bin/bash
# Builds WolfCare Malware Scanner.app from the Swift sources in
# Sources/, bundling the tested bash scanner (WolfCare.sh) as its backend.
set -e

APP_NAME="WolfCareGUI"
# Deliberately versionless - CFBundleName/CFBundleDisplayName in
# Info.plist carry the version (shown in the title bar and menu bar),
# so bumping a version doesn't require renaming the installed .app or
# breaking a Dock/Applications shortcut to it.
BUNDLE_NAME="WolfCare Malware Scanner.app"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "[1/5] Checking for Swift toolchain..."
if ! command -v swiftc >/dev/null 2>&1; then
    echo "swiftc not found. Install Xcode Command Line Tools first:"
    echo "  xcode-select --install"
    exit 1
fi

echo "[2/5] Cleaning previous build..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/$BUNDLE_NAME/Contents/MacOS"
mkdir -p "$BUILD_DIR/$BUNDLE_NAME/Contents/Resources"

echo "[3/5] Compiling Swift sources (universal binary: arm64 + x86_64)..."
# Deployment target is 12.0, matching Info.plist's LSMinimumSystemVersion.
# Was 13.0 (NavigationSplitView's floor); dropped to 12.0 by swapping
# NavigationSplitView for NavigationView and Table for a plain List
# (verified: `swiftc -target arm64-apple-macos12.0 -typecheck` and the
# x86_64 target both pass clean). Going lower than 12.0 would also need
# reworking @StateObject usage (11.0), every SF Symbol icon (11.0), and
# .foregroundStyle (12.0) throughout the app - SwiftUI's own hard floor
# is 10.15 regardless. The CLI scripts in cli_scripts/ have no version
# floor at all.
DEPLOYMENT_TARGET="12.0"
swiftc -O -target "arm64-apple-macos${DEPLOYMENT_TARGET}" \
    -o "$BUILD_DIR/arm64-bin" \
    "$SCRIPT_DIR"/Sources/*.swift
swiftc -O -target "x86_64-apple-macos${DEPLOYMENT_TARGET}" \
    -o "$BUILD_DIR/x86_64-bin" \
    "$SCRIPT_DIR"/Sources/*.swift
lipo -create -output "$BUILD_DIR/$BUNDLE_NAME/Contents/MacOS/$APP_NAME" \
    "$BUILD_DIR/arm64-bin" "$BUILD_DIR/x86_64-bin"
rm -f "$BUILD_DIR/arm64-bin" "$BUILD_DIR/x86_64-bin"

echo "[4/5] Assembling app bundle..."
cp "$SCRIPT_DIR/Info.plist" "$BUILD_DIR/$BUNDLE_NAME/Contents/Info.plist"
cp "$SCRIPT_DIR/icon.icns" "$BUILD_DIR/$BUNDLE_NAME/Contents/Resources/icon.icns"
cp "$SCRIPT_DIR/wolf_logo.png" "$BUILD_DIR/$BUNDLE_NAME/Contents/Resources/wolf_logo.png"
cp "$SCRIPT_DIR/WolfCare.sh" "$BUILD_DIR/$BUNDLE_NAME/Contents/Resources/WolfCare"
chmod +x "$BUILD_DIR/$BUNDLE_NAME/Contents/Resources/WolfCare"
chmod +x "$BUILD_DIR/$BUNDLE_NAME/Contents/MacOS/$APP_NAME"

echo "[5/5] Ad-hoc code signing..."
# Unlike our earlier bash-script apps, this is a compiled binary - Apple
# Silicon refuses to run ANY compiled Mach-O executable with zero signature
# at all, regardless of Gatekeeper/quarantine status. This is a different,
# stricter check than the "unidentified developer" warning; ad-hoc signing
# (no paid account needed) satisfies it.
codesign --force --deep --sign - "$BUILD_DIR/$BUNDLE_NAME"

echo ""
echo "Built: $BUILD_DIR/$BUNDLE_NAME"
echo "Run it with: open \"$BUILD_DIR/$BUNDLE_NAME\""
