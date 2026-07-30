# FullScanSecurity

Android app for the deepest possible on-device security scan — no root required.

## Features

- Scans as deep as possible without root access
- Detects security issues and suggests fixes
- UI inspired by iOS 26's Liquid Glass design language
- Free, no ads

## Platform

Built with Android Studio. Android only.
## Download Android App

[![Download Android App](https://img.shields.io/badge/Download-Android%20App-3DDC84?logo=android&logoColor=white)](https://github.com/lukaazman/FullScanSecurity/releases/latest/download/FullScanSecurity.apk)

The button downloads the APK attached to the latest GitHub Release. Android may ask you to allow installation from this source before installing the app.

## Build and release

Build the debug APK locally with:

```bash
./gradlew assembleDebug
```

Push a version tag to build the APK and create a GitHub Release automatically:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Pull requests and pushes to `main` run the Android build without creating a Release.
