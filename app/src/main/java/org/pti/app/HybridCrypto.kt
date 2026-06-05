package org.pti.app

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation
import org.bouncycastle.jcajce.spec.KEMExtractSpec
import org.bouncycastle.jcajce.spec.KEMGenerateSpec
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec
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
import java.security.spec.X509EncodedKeySpec

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
        val kpg = KeyPairGenerator.getInstance("ML-KEM", PROVIDER)
        kpg.initialize(MLKEMParameterSpec.ml_kem_768)
        val m = kpg.generateKeyPair()
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
