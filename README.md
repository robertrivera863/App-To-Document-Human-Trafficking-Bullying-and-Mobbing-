# Safe Witness (App)

An Android app to help people safely document evidence of crimes. Kotlin + Jetpack
Compose. Captures are intended to be encrypted on-device and uploaded off the phone.

> Status: **v0.1 — foundation build.** The app currently launches with a home
> screen. Camera, on-device encryption, and cloud upload are being added in layers.

## Download the APK (no build tools needed)
Every push to `main` triggers a GitHub Actions build that publishes a signed
**debug APK** to the **[Releases](../../releases)** page under the `latest` tag.
Download `app-debug.apk` there and install it (enable "install unknown apps").

## Build it yourself (optional)
Requires Android Studio (or JDK 17 + Android SDK):
```
gradle assembleDebug
```
APK lands in `app/build/outputs/apk/debug/`.

## Roadmap
- [x] Project foundation, builds to an installable APK via CI
- [ ] Camera capture (CameraX)
- [ ] On-device encryption of captures (AES-256 / Tink)
- [ ] Upload encrypted files to cloud storage
- [ ] Vault UI + secure delete
- [ ] PIN lock + calculator disguise

## Scope
For documenting crimes as a private citizen. Not for classified/official material.
Inspired by the open-source app [Tella](https://tella-app.org) by Horizontal.
