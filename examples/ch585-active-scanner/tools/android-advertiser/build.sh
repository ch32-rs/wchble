#!/bin/sh
# Manual APK build for the O2 controlled source; no Gradle or network required.
# The debug keystore is generated under build/ and is not committed.
set -eu
cd "$(dirname "$0")"
export JAVA_HOME=${JAVA_HOME:-/opt/homebrew/opt/openjdk@21}
export PATH="$JAVA_HOME/bin:$PATH"
SDK="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/35.0.0"
PLATFORM="$SDK/platforms/android-35/android.jar"
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
    --key-pass pass:android --out build/wchble-o2adv.apk build/aligned.apk
"$BT/apksigner" verify build/wchble-o2adv.apk
echo "built build/wchble-o2adv.apk"
