package org.pti.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * Uploads files to the user's own Yandex Disk via the REST API.
 *
 * Authentication uses an OAuth token the user obtains once and pastes into the app
 * (response_type=token flow). Uploaded files are viewable copies, so trusted contacts
 * (or an authorized agent) can retrieve them from the shared Yandex Disk folder.
 */
object YandexUploader {

    private const val BASE = "https://cloud-api.yandex.net/v1/disk"

    /** Creates the target folder if it doesn't already exist. Safe to call repeatedly. */
    suspend fun ensureFolder(token: String, path: String): Unit = withContext(Dispatchers.IO) {
        runCatching {
            val url = URL("$BASE/resources?path=${URLEncoder.encode(path, "UTF-8")}")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "PUT"
                setRequestProperty("Authorization", "OAuth $token")
                connectTimeout = 15000
                readTimeout = 15000
            }
            conn.responseCode // 201 = created, 409 = already exists; both are fine
            conn.disconnect()
        }
        Unit
    }

    /** Uploads [bytes] to [remotePath] on the user's Yandex Disk. */
    suspend fun upload(token: String, remotePath: String, bytes: ByteArray): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                val href = requestUploadHref(token, remotePath)
                putBytes(href, bytes)
            }
        }

    private fun requestUploadHref(token: String, remotePath: String): String {
        val encoded = URLEncoder.encode(remotePath, "UTF-8")
        val url = URL("$BASE/resources/upload?path=$encoded&overwrite=true")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            setRequestProperty("Authorization", "OAuth $token")
            connectTimeout = 15000
            readTimeout = 15000
        }
        val code = conn.responseCode
        if (code !in 200..299) {
            error("Could not get upload URL (HTTP $code). Check the token.")
        }
        conn.inputStream.use { input ->
            val body = BufferedReader(InputStreamReader(input)).readText()
            return JSONObject(body).getString("href")
        }
    }

    private fun putBytes(href: String, bytes: ByteArray) {
        val conn = (URL(href).openConnection() as HttpURLConnection).apply {
            requestMethod = "PUT"
            doOutput = true
            setRequestProperty("Content-Type", "application/octet-stream")
            connectTimeout = 30000
            readTimeout = 60000
        }
        conn.outputStream.use { it.write(bytes) }
        val code = conn.responseCode
        if (code !in 200..299) error("Upload failed (HTTP $code).")
        conn.disconnect()
    }
}
