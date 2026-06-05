package org.pti.app

import android.content.Context
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.io.File

/**
 * On-device encryption for the evidence vault.
 *
 * Uses Google Tink with AES-256-GCM. The encryption key is generated on the device
 * and protected by the Android Keystore (hardware-backed where available), so the
 * key never leaves the phone. AES-256 is considered quantum-resistant at rest.
 *
 * Plaintext is never written to disk: capture bytes are encrypted in memory and only
 * the ciphertext (.enc) is stored.
 */
object VaultCrypto {

    private const val KEYSET_NAME = "pti_keyset"
    private const val PREF_FILE = "pti_keyset_prefs"
    private const val MASTER_KEY_URI = "android-keystore://pti_master_key"
    private const val VAULT_DIR = "vault"

    @Volatile private var cached: Aead? = null

    private fun aead(context: Context): Aead {
        return cached ?: synchronized(this) {
            cached ?: build(context).also { cached = it }
        }
    }

    private fun build(context: Context): Aead {
        AeadConfig.register()
        val handle = AndroidKeysetManager.Builder()
            .withSharedPref(context, KEYSET_NAME, PREF_FILE)
            .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
            .withMasterKeyUri(MASTER_KEY_URI)
            .build()
            .keysetHandle
        return handle.getPrimitive(Aead::class.java)
    }

    private fun vaultDir(context: Context): File =
        File(context.filesDir, VAULT_DIR).apply { mkdirs() }

    /** Encrypts [plaintext] in memory and writes only the ciphertext to the vault. */
    fun encryptToVault(context: Context, plaintext: ByteArray, name: String): File {
        val out = File(vaultDir(context), "$name.enc")
        val ciphertext = aead(context).encrypt(plaintext, name.toByteArray())
        out.writeBytes(ciphertext)
        return out
    }

    /** Decrypts a vault file back to plaintext bytes (used for viewing / upload). */
    fun decryptFromVault(context: Context, file: File): ByteArray {
        val name = file.nameWithoutExtension
        return aead(context).decrypt(file.readBytes(), name.toByteArray())
    }

    fun vaultCount(context: Context): Int =
        vaultDir(context).listFiles { f -> f.extension == "enc" }?.size ?: 0

    /** Securely deletes all local copies. Copies already uploaded are unaffected. */
    fun wipeVault(context: Context): Int {
        val files = vaultDir(context).listFiles() ?: return 0
        var deleted = 0
        files.forEach { if (it.delete()) deleted++ }
        return deleted
    }
}
