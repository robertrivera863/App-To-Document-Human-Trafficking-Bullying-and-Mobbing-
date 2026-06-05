package org.pti.app

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation
import org.bouncycastle.jcajce.spec.KEMExtractSpec
import org.bouncycastle.jcajce.spec.KEMGenerateSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Zero-knowledge hybrid encryption. The storage server only ever holds the bundle
 * below; the private keys never leave the holder's device, so the server can never
 * decrypt.
 *
 * Scheme (an attacker must break BOTH key-exchanges at once):
 *   - Classical KEM: X25519 (ephemeral) -> shared secret s1
 *   - Post-quantum KEM: ML-KEM-768 (NIST FIPS 203, Level 3) -> shared secret s2
 *   - KEK = HKDF-SHA256(s1 || s2)
 *   - A random AES-256 file key encrypts the data with AES-256-GCM
 *   - The file key is wrapped with the KEK using AES-256-GCM
 *
 * This module is intentionally free of Android APIs so it runs as a plain JVM unit
 * test (see HybridCryptoTest) — the encrypt/decrypt round-trip is verified in CI.
 */
object HybridCrypto {

    private const val PROVIDER = "BC"
    private const val HKDF_INFO = "PTI-hybrid-v1"
    private const val GCM_TAG_BITS = 128
    private const val FORMAT_VERSION = 1

    private fun ensureProvider() {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /** A recipient's two keypairs. The private keys must be backed up offline and never uploaded. */
    class Recipient(
        val x25519: KeyPair,
        val mlkem: KeyPair,
    )

    fun generateRecipient(): Recipient {
        ensureProvider()
        val x = KeyPairGenerator.getInstance("X25519", PROVIDER).generateKeyPair()
        // Parameterized algorithm name avoids needing a version-specific ParameterSpec class.
        val m = KeyPairGenerator.getInstance("ML-KEM-768", PROVIDER).generateKeyPair()
        return Recipient(x, m)
    }

    fun encrypt(plaintext: ByteArray, x25519Public: PublicKey, mlkemPublic: PublicKey): ByteArray {
        ensureProvider()
        val rnd = SecureRandom()

        // Classical KEM: ephemeral X25519 -> s1
        val ephemeral = KeyPairGenerator.getInstance("X25519", PROVIDER).generateKeyPair()
        val ka = KeyAgreement.getInstance("X25519", PROVIDER)
        ka.init(ephemeral.private)
        ka.doPhase(x25519Public, true)
        val s1 = ka.generateSecret()

        // Post-quantum KEM: ML-KEM-768 encapsulate -> s2 + encapsulation
        val kg = KeyGenerator.getInstance("ML-KEM", PROVIDER)
        kg.init(KEMGenerateSpec(mlkemPublic, "AES"), rnd)
        val enc = kg.generateKey() as SecretKeyWithEncapsulation
        val s2 = enc.encoded
        val kemCiphertext = enc.encapsulation

        val kek = hkdfSha256(s1 + s2, HKDF_INFO, 32)

        // Encrypt data with a fresh AES-256 file key
        val fileKey = ByteArray(32).also { rnd.nextBytes(it) }
        val dataNonce = ByteArray(12).also { rnd.nextBytes(it) }
        val dataCiphertext = aesGcm(Cipher.ENCRYPT_MODE, fileKey, dataNonce, plaintext)

        // Wrap the file key with the KEK
        val wrapNonce = ByteArray(12).also { rnd.nextBytes(it) }
        val wrappedKey = aesGcm(Cipher.ENCRYPT_MODE, kek, wrapNonce, fileKey)

        return pack(
            byteArrayOf(FORMAT_VERSION.toByte()),
            ephemeral.public.encoded,
            kemCiphertext,
            wrapNonce,
            wrappedKey,
            dataNonce,
            dataCiphertext,
        )
    }

    fun decrypt(bundle: ByteArray, x25519Private: PrivateKey, mlkemPrivate: PrivateKey): ByteArray {
        ensureProvider()
        val parts = unpack(bundle)
        require(parts.size == 7 && parts[0].isNotEmpty() && parts[0][0].toInt() == FORMAT_VERSION) {
            "Unrecognized bundle format"
        }

        val ephemeralPub = KeyFactory.getInstance("X25519", PROVIDER)
            .generatePublic(X509EncodedKeySpec(parts[1]))
        val ka = KeyAgreement.getInstance("X25519", PROVIDER)
        ka.init(x25519Private)
        ka.doPhase(ephemeralPub, true)
        val s1 = ka.generateSecret()

        val kg = KeyGenerator.getInstance("ML-KEM", PROVIDER)
        kg.init(KEMExtractSpec(mlkemPrivate, parts[2], "AES"))
        val dec = kg.generateKey() as SecretKeyWithEncapsulation
        val s2 = dec.encoded

        val kek = hkdfSha256(s1 + s2, HKDF_INFO, 32)
        val fileKey = aesGcm(Cipher.DECRYPT_MODE, kek, parts[3], parts[4])
        return aesGcm(Cipher.DECRYPT_MODE, fileKey, parts[5], parts[6])
    }

    // --- Key export / import (Base64 text the user backs up or hands to trusted family) ---

    /** Public-key bundle: kept in the app; what files are encrypted to. Safe to share. */
    fun exportPublicKeys(recipient: Recipient): String =
        Base64.getEncoder().encodeToString(
            pack(recipient.x25519.public.encoded, recipient.mlkem.public.encoded)
        )

    /** Private-key bundle: the ONLY thing that can decrypt. Back up offline; never upload. */
    fun exportPrivateKeys(recipient: Recipient): String =
        Base64.getEncoder().encodeToString(
            pack(recipient.x25519.private.encoded, recipient.mlkem.private.encoded)
        )

    /** Encrypts to a public-key bundle from [exportPublicKeys]. */
    fun encryptTo(plaintext: ByteArray, publicBundle: String): ByteArray {
        ensureProvider()
        val parts = unpack(Base64.getDecoder().decode(publicBundle))
        val x = KeyFactory.getInstance("X25519", PROVIDER).generatePublic(X509EncodedKeySpec(parts[0]))
        val m = KeyFactory.getInstance("ML-KEM", PROVIDER).generatePublic(X509EncodedKeySpec(parts[1]))
        return encrypt(plaintext, x, m)
    }

    /** Decrypts using a private-key bundle from [exportPrivateKeys] (what family holds). */
    fun decryptWith(bundle: ByteArray, privateBundle: String): ByteArray {
        ensureProvider()
        val parts = unpack(Base64.getDecoder().decode(privateBundle))
        val x = KeyFactory.getInstance("X25519", PROVIDER).generatePrivate(PKCS8EncodedKeySpec(parts[0]))
        val m = KeyFactory.getInstance("ML-KEM", PROVIDER).generatePrivate(PKCS8EncodedKeySpec(parts[1]))
        return decrypt(bundle, x, m)
    }

    // --- Multi-recipient: one ciphertext that several key-holders can each open ---
    private const val MULTI_VERSION = 2

    /**
     * Encrypts [plaintext] once, then wraps the file key separately for each recipient's
     * public-key bundle. Any one of [publicBundles] (friend, family, lawyer, AI) can decrypt.
     */
    fun encryptToMany(plaintext: ByteArray, publicBundles: List<String>): ByteArray {
        ensureProvider()
        require(publicBundles.isNotEmpty()) { "At least one recipient is required" }
        val rnd = SecureRandom()

        val fileKey = ByteArray(32).also { rnd.nextBytes(it) }
        val dataNonce = ByteArray(12).also { rnd.nextBytes(it) }
        val dataCiphertext = aesGcm(Cipher.ENCRYPT_MODE, fileKey, dataNonce, plaintext)

        val blocks = publicBundles.map { wrapKeyFor(it, fileKey, rnd) }
        return pack(byteArrayOf(MULTI_VERSION.toByte()), dataNonce, dataCiphertext, *blocks.toTypedArray())
    }

    /** Decrypts a multi-recipient bundle with one holder's private-key bundle. */
    fun decryptFromMany(bundle: ByteArray, privateBundle: String): ByteArray {
        ensureProvider()
        val parts = unpack(bundle)
        require(parts.size >= 4 && parts[0].isNotEmpty() && parts[0][0].toInt() == MULTI_VERSION) {
            "Unrecognized multi-recipient bundle"
        }
        val dataNonce = parts[1]
        val dataCiphertext = parts[2]
        val priv = unpack(Base64.getDecoder().decode(privateBundle))
        val xPriv = KeyFactory.getInstance("X25519", PROVIDER).generatePrivate(PKCS8EncodedKeySpec(priv[0]))
        val mPriv = KeyFactory.getInstance("ML-KEM", PROVIDER).generatePrivate(PKCS8EncodedKeySpec(priv[1]))

        for (i in 3 until parts.size) {
            val fileKey = runCatching { unwrapKeyWith(parts[i], xPriv, mPriv) }.getOrNull() ?: continue
            return aesGcm(Cipher.DECRYPT_MODE, fileKey, dataNonce, dataCiphertext)
        }
        error("This key cannot open the file (not an authorized recipient)")
    }

    private fun wrapKeyFor(publicBundle: String, fileKey: ByteArray, rnd: SecureRandom): ByteArray {
        val pub = unpack(Base64.getDecoder().decode(publicBundle))
        val xPub = KeyFactory.getInstance("X25519", PROVIDER).generatePublic(X509EncodedKeySpec(pub[0]))
        val mPub = KeyFactory.getInstance("ML-KEM", PROVIDER).generatePublic(X509EncodedKeySpec(pub[1]))

        val ephemeral = KeyPairGenerator.getInstance("X25519", PROVIDER).generateKeyPair()
        val ka = KeyAgreement.getInstance("X25519", PROVIDER)
        ka.init(ephemeral.private)
        ka.doPhase(xPub, true)
        val s1 = ka.generateSecret()

        val kg = KeyGenerator.getInstance("ML-KEM", PROVIDER)
        kg.init(KEMGenerateSpec(mPub, "AES"), rnd)
        val enc = kg.generateKey() as SecretKeyWithEncapsulation

        val kek = hkdfSha256(s1 + enc.encoded, HKDF_INFO, 32)
        val wrapNonce = ByteArray(12).also { rnd.nextBytes(it) }
        val wrapped = aesGcm(Cipher.ENCRYPT_MODE, kek, wrapNonce, fileKey)
        return pack(ephemeral.public.encoded, enc.encapsulation, wrapNonce, wrapped)
    }

    private fun unwrapKeyWith(block: ByteArray, xPriv: PrivateKey, mPriv: PrivateKey): ByteArray {
        val b = unpack(block)
        val ephPub = KeyFactory.getInstance("X25519", PROVIDER).generatePublic(X509EncodedKeySpec(b[0]))
        val ka = KeyAgreement.getInstance("X25519", PROVIDER)
        ka.init(xPriv)
        ka.doPhase(ephPub, true)
        val s1 = ka.generateSecret()

        val kg = KeyGenerator.getInstance("ML-KEM", PROVIDER)
        kg.init(KEMExtractSpec(mPriv, b[1], "AES"))
        val dec = kg.generateKey() as SecretKeyWithEncapsulation

        val kek = hkdfSha256(s1 + dec.encoded, HKDF_INFO, 32)
        return aesGcm(Cipher.DECRYPT_MODE, kek, b[2], b[3])
    }

    private fun aesGcm(mode: Int, key: ByteArray, nonce: ByteArray, input: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        return cipher.doFinal(input)
    }

    /** Minimal HKDF (RFC 5869) over HMAC-SHA256, sufficient for a single 32-byte key. */
    private fun hkdfSha256(ikm: ByteArray, info: String, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256")) // salt = zeros
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(info.toByteArray())
        mac.update(0x01)
        val okm = mac.doFinal()
        return okm.copyOf(length)
    }

    private fun pack(vararg parts: ByteArray): ByteArray {
        val bos = ByteArrayOutputStream()
        DataOutputStream(bos).use { out ->
            out.writeInt(parts.size)
            for (p in parts) {
                out.writeInt(p.size)
                out.write(p)
            }
        }
        return bos.toByteArray()
    }

    private fun unpack(data: ByteArray): List<ByteArray> {
        DataInputStream(ByteArrayInputStream(data)).use { input ->
            val count = input.readInt()
            return (0 until count).map {
                val len = input.readInt()
                ByteArray(len).also { input.readFully(it) }
            }
        }
    }
}
