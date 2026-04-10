---
name: mobile-app-acquisition
description: Automated mobile app download from running emulators/simulators for security testing. Detects Android emulators and iOS simulators, downloads APKs/IPAs from app stores, pulls split APKs, and triggers post-download static analysis. Referenced by /intigriti, /hackerone, and /mobile-security.
---

# Mobile App Acquisition

Automatically downloads mobile apps from running emulators/simulators when iOS or Android assets appear in scope.

## Detection: Find Running Emulators

```bash
# Android emulators
adb devices | grep -E "emulator|device$"

# iOS simulators
xcrun simctl list devices booted
```

## Android App Download

```bash
# 1. Identify the target package from scope (e.g., de.bmw.connected.mobile20.row)
PACKAGE="<package_id_from_scope>"

# 2. Open Play Store on the emulator to install
adb shell am start -a android.intent.action.VIEW -d "market://details?id=${PACKAGE}"

# 3. Wait for user to complete install, then verify
adb shell pm list packages | grep "${PACKAGE}"

# 4. Pull APK for static analysis
APK_PATH=$(adb shell pm path "${PACKAGE}" | sed 's/package://')
adb pull "${APK_PATH}" "./outputs/apps/${PACKAGE}.apk"

# 5. If multiple splits (split APKs), pull all
adb shell pm path "${PACKAGE}" | while read -r line; do
  path=$(echo "$line" | sed 's/package://')
  filename=$(basename "$path")
  adb pull "$path" "./outputs/apps/${filename}"
done
```

## iOS App Download

```bash
# 1. Identify the App Store ID from scope (e.g., 1519034860)
APP_ID="<appstore_id_from_scope>"

# 2. Get booted simulator UDID
UDID=$(xcrun simctl list devices booted -j | python3 -c "
import json, sys
data = json.load(sys.stdin)
for runtime, devices in data['devices'].items():
    for d in devices:
        if d['state'] == 'Booted':
            print(d['udid']); break
")

# 3. Open App Store on simulator
xcrun simctl openurl "${UDID}" "itms-apps://apps.apple.com/app/id${APP_ID}"

# 4. Alternative: use ipatool if available for direct IPA download
ipatool download -b "<bundle_id>" -o "./outputs/apps/"

# 5. For real devices connected via USB
ideviceinstaller -l | grep "<bundle_id>"
```

## Post-Download Analysis

```
- [ ] Static analysis with MobSF (if /mobile-security skill available)
- [ ] Extract AndroidManifest.xml / Info.plist
- [ ] Identify API endpoints, hardcoded secrets, certificate pinning
- [ ] Feed discovered endpoints back to web/API Pentester agents
```

## Critical Rules

- **Auto-download** when emulators are available and mobile assets are in scope
- **Never skip** mobile app download when emulators are running
- Check mobile/desktop-specific exclusions BEFORE analysis (certificate pinning, obfuscation, path disclosure, root detection are commonly OOS)
