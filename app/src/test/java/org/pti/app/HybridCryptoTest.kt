package org.pti.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class HybridCryptoTest {

    @Test
    fun encryptThenDecrypt_returnsOriginal() {
        val recipient = HybridCrypto.generateRecipient()
        val message = "evidence bytes — hybrid X25519 + ML-KEM-768 ✓".toByteArray()

        val bundle = HybridCrypto.encrypt(
            message,
            recipient.x25519.public,
            recipient.mlkem.public,
        )
        val recovered = HybridCrypto.decrypt(
            bundle,
            recipient.x25519.private,
            recipient.mlkem.private,
        )

        assertArrayEquals(message, recovered)
    }

    @Test
    fun ciphertext_doesNotContainPlaintext() {
        val recipient = HybridCrypto.generateRecipient()
        val secret = "TOP-SECRET-MARKER-9931".toByteArray()

        val bundle = HybridCrypto.encrypt(
            secret,
            recipient.x25519.public,
            recipient.mlkem.public,
        )

        // The marker must never appear in the encrypted bundle the server would hold.
        assertFalse(
            "Plaintext leaked into ciphertext",
            String(bundle, Charsets.ISO_8859_1).contains("TOP-SECRET-MARKER-9931"),
        )
    }

    @Test(expected = Exception::class)
    fun wrongKey_failsToDecrypt() {
        val a = HybridCrypto.generateRecipient()
        val b = HybridCrypto.generateRecipient()
        val bundle = HybridCrypto.encrypt("nope".toByteArray(), a.x25519.public, a.mlkem.public)

        // Decrypting with a different recipient's keys must fail (AES-GCM auth tag).
        HybridCrypto.decrypt(bundle, b.x25519.private, b.mlkem.private)
    }
}
