#!/bin/sh
# Manual APK build for the controlled C1 GATT peripheral; no Gradle or network
# required. The debug keystore is generated outside the tree and not committed.
set -eu
cd "$(dirname "$0")"

# --- Toolchain -----------------------------------------------------------
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then
    :
elif [ -x /opt/homebrew/opt/openjdk@21/bin/javac ]; then
    JAVA_HOME=/opt/homebrew/opt/openjdk@21
    export JAVA_HOME
elif command -v javac >/dev/null 2>&1 && javac -version >/dev/null 2>&1; then
    :
else
    echo "error: Java compiler not found; set JAVA_HOME" >&2
    exit 1
fi
[ -n "${JAVA_HOME:-}" ] && PATH="$JAVA_HOME/bin:$PATH"
export PATH

SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
BT="${ANDROID_BUILD_TOOLS:-$SDK/build-tools/35.0.0}"
PLATFORM="${ANDROID_PLATFORM:-$SDK/platforms/android-35/android.jar}"

if [ ! -x "$BT/aapt2" ] || [ ! -x "$BT/d8" ] || [ ! -x "$BT/apksigner" ]; then
    echo "error: Android build-tools not found at $BT" >&2
    echo "       set ANDROID_BUILD_TOOLS or ANDROID_SDK_ROOT" >&2
    exit 1
fi
if [ ! -f "$PLATFORM" ]; then
    echo "error: Android platform jar not found at $PLATFORM" >&2
    echo "       set ANDROID_PLATFORM or ANDROID_SDK_ROOT" >&2
    exit 1
fi

APK=build/android-gatt.apk

# --- Build ---------------------------------------------------------------
rm -rf build
mkdir -p build/classes build/dex
javac -source 8 -target 8 -classpath "$PLATFORM" -d build/classes \
    $(find src -name '*.java')
jar cf build/classes.jar -C build/classes .
"$BT/d8" --lib "$PLATFORM" --min-api 26 --output build/dex build/classes.jar
"$BT/aapt2" link -o build/base.apk -I "$PLATFORM" \
    --manifest AndroidManifest.xml --min-sdk-version 26 --target-sdk-version 35
(cd build/dex && zip -q ../base.apk classes.dex)
"$BT/zipalign" -f 4 build/base.apk build/aligned.apk

# A stable debug key outside the tree, so `adb install -r` keeps the runtime
# permission grant. Standard Android debug-keystore location.
KEYSTORE="${ANDROID_DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}"
mkdir -p "$(dirname "$KEYSTORE")"
if [ ! -f "$KEYSTORE" ]; then
    keytool -genkeypair -keystore "$KEYSTORE" -alias androiddebugkey \
        -storepass android -keypass android -keyalg RSA -keysize 2048 \
        -validity 10000 -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
fi

"$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android \
    --key-pass pass:android --out "$APK" build/aligned.apk
"$BT/apksigner" verify "$APK" >&2

# Last line is the APK path (machine-readable).
echo "$APK"
