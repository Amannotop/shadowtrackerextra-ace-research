#!/bin/zsh
# build.sh — reproducible build without theos (exact clang flags), fallback when theos absent
# language: bash, file: build.sh, runtime: Xcode 26.6 clang, macOS 26.4.1 arm64
# *watch for SDK path drift: xcrun --show-sdk-path must match App. H pin; mismatch -> §18.5*
set -euo pipefail
SDK=$(xcrun --show-sdk-path --sdk iphoneos)
echo "[build] SDK=$SDK"
echo "[build] clang=$(clang --version | head -1)"
clang -arch arm64 -isysroot "$SDK" -mios-version-min=15.0 \
  -fobjc-arc -Wall -Wextra -Wno-unused-parameter \
  -dynamiclib -o bypass.dylib bypass.x payload_spoofer.m \
  -framework Foundation -framework Security
echo "[build] bypass.dylib OK"
codesign -s - --entitlements entitlements.xml -f bypass.dylib
echo "[build] signed OK"
