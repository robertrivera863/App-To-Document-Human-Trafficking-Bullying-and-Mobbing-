package org.pti.app

import android.content.Context

/**
 * The list of people approved to decrypt the evidence. Each entry holds a label and
 * that person's PUBLIC key bundle. Files are encrypted to every approved public key,
 * so only these people (who hold the matching private key you gave them) can open them.
 *
 * "Approval" = being on this list. "Revoke" = removed here, so future uploads can no
 * longer be opened by that person.
 */
object RecipientStore {

    private const val PREF = "pti_recipients"
    private const val KEY = "list"

    data class Entry(val label: String, val publicBundle: String)

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun list(context: Context): List<Entry> {
        val raw = prefs(context).getString(KEY, "").orEmpty()
        if (raw.isBlank()) return emptyList()
        return raw.split("\n").mapNotNull { line ->
            val idx = line.indexOf('|')
            if (idx <= 0) null else Entry(line.substring(0, idx), line.substring(idx + 1))
        }
    }

    fun publicBundles(context: Context): List<String> = list(context).map { it.publicBundle }

    fun add(context: Context, label: String, publicBundle: String) {
        val cleaned = label.replace("\n", " ").replace("|", "/").ifBlank { "Recipient" }
        save(context, list(context) + Entry(cleaned, publicBundle))
    }

    fun remove(context: Context, publicBundle: String) {
        save(context, list(context).filterNot { it.publicBundle == publicBundle })
    }

    private fun save(context: Context, entries: List<Entry>) {
        val raw = entries.joinToString("\n") { "${it.label}|${it.publicBundle}" }
        prefs(context).edit().putString(KEY, raw).apply()
    }
}
