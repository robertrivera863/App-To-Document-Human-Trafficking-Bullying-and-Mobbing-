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

    @Test
    fun exportedKeys_roundTrip() {
        val recipient = HybridCrypto.generateRecipient()
        val publicBundle = HybridCrypto.exportPublicKeys(recipient)
        val privateBundle = HybridCrypto.exportPrivateKeys(recipient)

        val message = "shared evidence via exported keys".toByteArray()
        val bundle = HybridCrypto.encryptTo(message, publicBundle)
        val recovered = HybridCrypto.decryptWith(bundle, privateBundle)

        assertArrayEquals(message, recovered)
    }

    @Test
    fun multiRecipient_eachHolderCanDecrypt() {
        val mom = HybridCrypto.generateRecipient()
        val friend = HybridCrypto.generateRecipient()
        val message = "evidence for multiple trusted people".toByteArray()

        val bundle = HybridCrypto.encryptToMany(
            message,
            listOf(HybridCrypto.exportPublicKeys(mom), HybridCrypto.exportPublicKeys(friend)),
        )

        assertArrayEquals(message, HybridCrypto.decryptFromMany(bundle, HybridCrypto.exportPrivateKeys(mom)))
        assertArrayEquals(message, HybridCrypto.decryptFromMany(bundle, HybridCrypto.exportPrivateKeys(friend)))
    }

    @Test(expected = Exception::class)
    fun multiRecipient_nonRecipientCannotDecrypt() {
        val mom = HybridCrypto.generateRecipient()
        val stranger = HybridCrypto.generateRecipient()
        val bundle = HybridCrypto.encryptToMany("x".toByteArray(), listOf(HybridCrypto.exportPublicKeys(mom)))

        HybridCrypto.decryptFromMany(bundle, HybridCrypto.exportPrivateKeys(stranger))
    }
}
