# Protection for Target Individuals — Design & Architecture

## 1. Problem
People who are bullied, mobbed, harassed, or trafficked often need to **document
what is happening to them** but have no safe way to do it. Evidence on a phone can be
discovered, deleted, or altered — and the person is frequently not in a position to
protect it themselves. The goal of this project is a phone app that lets such a person
**capture evidence, protect it with strong encryption, and get copies into trusted
hands** so it cannot be quietly concealed or destroyed.

## 2. Scope (and deliberate non-goals)
**In scope:** documenting crimes/abuse as a private citizen, encrypting that evidence,
and sharing it with trusted people the user chooses.

**Deliberately NOT built, for safety reasons:**
- **No remote access *into* the phone** (no remote camera control, no on-demand file
  pulling). That capability is functionally stalkerware — the exact tool abusers use
  against victims — so the design never exposes the device to inbound connections.
- **No integration with law-enforcement/government systems.** An app cannot connect to
  those; it can only help a user *gather and share* evidence to hand off themselves.
- **Not for classified/official material.** That is a different legal domain requiring
  protected channels and counsel, not a consumer app.

Stating these limits explicitly is part of the design: a tool for vulnerable people
must not over-promise capabilities it cannot safely deliver.

## 3. Architecture
A single-module Android app (Kotlin + Jetpack Compose). Components:

| Component | Responsibility |
|---|---|
| `MainActivity` (Compose UI) | Screens: capture, key management, view/decrypt, panic wipe |
| `VaultCrypto` | On-device encryption of captures (AES-256-GCM via Google Tink + Android Keystore) |
| `HybridCrypto` | Post-quantum hybrid encryption for sharing (X25519 + ML-KEM-768 + AES-256-GCM) |
| `RecipientStore` | The list of approved people (their public keys) |
| `YandexUploader` | Optional upload of encrypted bundles to the user's Yandex Disk |

**Data flow:** capture → encrypt on device → (optional) encrypt to approved recipients
→ upload ciphertext to Yandex → recipients download and decrypt with their private key.
The phone only ever **pushes data out**; nothing reaches in.

## 4. Security model
**Threat model:** the adversary may seize or inspect the phone, intercept network
traffic, or access the storage server. The adversary is *not* assumed to have a quantum
computer today, but "harvest-now-decrypt-later" is considered.

**Protections:**
- **At rest on the phone:** AES-256-GCM, key in the Android Keystore (never leaves device).
- **In transit:** HTTPS/TLS.
- **At rest in the cloud (zero-knowledge):** each file is sealed with a **hybrid KEM** —
  X25519 (classical) and ML-KEM-768 (NIST FIPS 203, Level 3) shared secrets are combined
  via HKDF-SHA256 into a key-encryption key, which wraps a random AES-256-GCM file key. An
  attacker must defeat **both** key exchanges simultaneously. The server holds only
  ciphertext and the key-encapsulation blob; it can never decrypt.
- **Access control = key possession.** Only holders of an approved private key can decrypt.
  "Approval" is handing someone a key; "revocation" is removing them so *future* uploads
  no longer include them.
- **Multi-recipient:** one ciphertext can be opened by several key-holders (e.g. family
  and a lawyer), each with their own key.

## 5. Key design decisions & trade-offs
- **Yandex Disk over Google Drive:** chosen by the project owner; the app treats cloud
  storage as a dumb, untrusted store (it only ever sees ciphertext), so the provider is
  interchangeable.
- **Encryption vs. easy viewing:** real end-to-end encryption means recipients need a key
  and the app to view — not a one-click public link. This trade was made deliberately in
  favour of evidence integrity and confidentiality.
- **Key backup is mandatory, not optional:** with zero-knowledge encryption, a lost
  private key means permanently unrecoverable evidence. Giving the private key to trusted
  family *is* the backup, and it is what makes the "77" wipe safe.
- **"77" panic wipe:** a normal app cannot factory-reset the phone, so "wipe" means
  securely erasing the app's vault, local key, token, and recipient list. Because the
  evidence is already uploaded (encrypted) and family hold the key, wiping the phone does
  not destroy the evidence — only the local traces.
- **Push-only, never inbound:** rejected remote-into-phone access on safety grounds (§2).

## 6. Verification
- **Cryptography is unit-tested in CI** (`HybridCryptoTest`): encrypt→decrypt round-trip,
  multi-recipient (each holder decrypts), wrong-key rejection, and exported-key round-trip.
- **GitHub Actions** runs the tests, then builds the APK on every push to `main`, and
  publishes the APK to Releases. A green build is reproducible proof the project compiles
  and the encryption behaves correctly.
- **Device-level testing** (camera, UI, upload) is performed by installing the APK on an
  Android phone.

## 7. Limitations & honest notes
- Android **Safe Mode** cannot be blocked by a normal app; evidence already uploaded is
  the mitigation.
- The cryptography should be **independently reviewed by a security expert** before any
  real-world reliance — unit tests prove behaviour, not the absence of subtle flaws.
- The app preserves and protects evidence; it does not make anyone invisible or defeat a
  determined forensic search of an unlocked device.

## 8. Development & tooling
This project was built with **AI-assisted development** (an AI coding assistant) under
the direction of the project owner, who made the product and security decisions
(storage choice, encryption requirements, scope boundaries, feature set). Per good
academic practice, AI assistance should be disclosed in line with the course's policy.

## 9. Future work
- Recipient-side companion experience and key import UX
- Selective sharing (choose which captures go to which recipients)
- Video and document capture
- Optional disguise/launcher concealment
- Formal third-party cryptography review
