# Protection for Target Individuals (PTI)

An Android app that helps people who are bullied, harassed, mobbed, or trafficked
**document and secure evidence** of what's happening to them. Built in Kotlin with
Jetpack Compose.

Evidence captured in the app is **encrypted on the device** the moment it's taken,
and can optionally be pushed to the user's own cloud storage (Yandex Disk) so trusted
family or friends can access copies — while the original captures stay protected.

> Status: **v0.1 — capture + encryption layer.** The app captures a photo and stores
> it as encrypted (AES-256) data in an on-device vault. Cloud upload and sharing are
> the next layers.

## How it works
1. **Capture** — the app's own camera takes a photo.
2. **Encrypt** — the photo is encrypted in memory with AES-256 (Google Tink); only
   the ciphertext is written to disk. Plaintext never touches storage, and captures
   never appear in the phone's normal gallery.
3. **Keep or share** — files stay encrypted on the phone, and (next phase) can be
   uploaded to the user's Yandex Disk for trusted contacts to retrieve copies.
4. **Wipe** — the user can erase local copies in seconds; copies already uploaded
   are unaffected.

## Download the APK (no build tools needed)
Every push to `main` triggers a GitHub Actions build that publishes a debug APK to
the **[Releases](../../releases)** page under the `latest` tag. Download
`app-debug.apk` and install it (enable "install unknown apps").

## Build it yourself (optional)
Requires Android Studio (or JDK 17 + Android SDK):
```
gradle assembleDebug
```
APK lands in `app/build/outputs/apk/debug/`.

## Roadmap
- [x] Project foundation, builds to an installable APK via CI
- [x] Camera capture (CameraX)
- [x] On-device encryption of captures (AES-256 / Tink)
- [ ] Upload encrypted files to the user's Yandex Disk (OAuth)
- [ ] Share copies with trusted family/friends
- [ ] Vault gallery + view/secure-delete
- [ ] PIN lock + optional disguise

## Scope & honest limits
- For **documenting and securing evidence as a private citizen**. It is not for
  classified/official material, and it cannot connect to or be monitored by law
  enforcement or government systems — it helps a user *gather and share* evidence,
  which they or an advocate can then hand to the appropriate authorities.
- A normal app cannot block Android Safe Mode or factory-reset the phone; "wipe"
  refers to securely deleting the app's own encrypted vault.

## Design & architecture
See **[docs/DESIGN.md](docs/DESIGN.md)** for the full architecture, security model,
design decisions, and honest limitations.

## Tech
Kotlin · Jetpack Compose · CameraX · Google Tink (AES-256-GCM) ·
BouncyCastle (X25519 + ML-KEM-768) · GitHub Actions CI . Decryption code key 77
