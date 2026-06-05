package org.pti.app

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AppRoot()
                }
            }
        }
    }
}

@Composable
fun AppRoot() {
    var screen by remember { mutableStateOf("home") }
    when (screen) {
        "camera" -> CameraScreen(onDone = { screen = "home" })
        "recipients" -> RecipientsScreen(onBack = { screen = "home" })
        else -> HomeScreen(
            onOpenCamera = { screen = "camera" },
            onManageKeys = { screen = "recipients" },
        )
    }
}

@Composable
fun HomeScreen(onOpenCamera: () -> Unit, onManageKeys: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefs = remember { context.getSharedPreferences("pti_prefs", Context.MODE_PRIVATE) }

    var count by remember { mutableStateOf(VaultCrypto.vaultCount(context)) }
    var token by remember { mutableStateOf(prefs.getString("yandex_token", "").orEmpty()) }
    var uploading by remember { mutableStateOf(false) }
    var autoUpload by remember { mutableStateOf(prefs.getBoolean("auto_upload", false)) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            "Protection for Target Individuals",
            style = MaterialTheme.typography.headlineMedium,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "$count item(s) secured & encrypted on this phone",
            textAlign = TextAlign.Center
        )

        Spacer(Modifier.height(24.dp))
        Button(onClick = onOpenCamera) { Text("Secure a photo") }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = onManageKeys) { Text("Who can access (keys)") }

        Spacer(Modifier.height(24.dp))
        Text("Yandex Disk (optional)", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = token,
            onValueChange = { token = it },
            label = { Text("Paste your Yandex OAuth token") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = {
            prefs.edit().putString("yandex_token", token.trim()).apply()
            Toast.makeText(context, "Token saved", Toast.LENGTH_SHORT).show()
        }) { Text("Save token") }

        Spacer(Modifier.height(8.dp))
        Button(
            enabled = token.isNotBlank() && !uploading,
            onClick = {
                val recipients = RecipientStore.publicBundles(context)
                if (recipients.isEmpty()) {
                    Toast.makeText(
                        context,
                        "Add at least one person under \"Who can access\" first",
                        Toast.LENGTH_LONG
                    ).show()
                    return@Button
                }
                uploading = true
                scope.launch {
                    val t = token.trim()
                    YandexUploader.ensureFolder(t, "/PTI")
                    var ok = 0
                    var fail = 0
                    for (file in VaultCrypto.listVault(context)) {
                        val plain = runCatching { VaultCrypto.decryptFromVault(context, file) }
                            .getOrNull() ?: run { fail++; continue }
                        val sealed = HybridCrypto.encryptToMany(plain, recipients)
                        val remote = "/PTI/${file.nameWithoutExtension}.ptq"
                        if (YandexUploader.upload(t, remote, sealed).isSuccess) ok++ else fail++
                    }
                    uploading = false
                    Toast.makeText(
                        context, "Uploaded $ok, failed $fail", Toast.LENGTH_LONG
                    ).show()
                }
            }
        ) { Text(if (uploading) "Uploading…" else "Upload all to Yandex Disk") }

        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(
                checked = autoUpload,
                onCheckedChange = {
                    autoUpload = it
                    prefs.edit().putBoolean("auto_upload", it).apply()
                }
            )
            Spacer(Modifier.height(0.dp))
            Text("  Auto-upload new captures")
        }

        Spacer(Modifier.height(24.dp))
        OutlinedButton(onClick = {
            val n = VaultCrypto.wipeVault(context)
            count = VaultCrypto.vaultCount(context)
            Toast.makeText(context, "Wiped $n file(s) from this phone", Toast.LENGTH_SHORT).show()
        }) { Text("Wipe vault on this phone") }
    }
}

@Composable
fun CameraScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    val prefs = remember { context.getSharedPreferences("pti_prefs", Context.MODE_PRIVATE) }

    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasPermission = granted
        if (!granted) onDone()
    }
    LaunchedEffect(Unit) {
        if (!hasPermission) launcher.launch(Manifest.permission.CAMERA)
    }

    if (!hasPermission) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("Camera permission is needed to capture evidence.")
        }
        return
    }

    val imageCapture = remember { ImageCapture.Builder().build() }

    Box(Modifier.fillMaxSize()) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val future = ProcessCameraProvider.getInstance(ctx)
                future.addListener({
                    val provider = future.get()
                    val preview = Preview.Builder().build().also {
                        it.setSurfaceProvider(previewView.surfaceProvider)
                    }
                    provider.unbindAll()
                    provider.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                        imageCapture
                    )
                }, ContextCompat.getMainExecutor(ctx))
                previewView
            }
        )
        Button(
            onClick = {
                imageCapture.takePicture(
                    ContextCompat.getMainExecutor(context),
                    object : ImageCapture.OnImageCapturedCallback() {
                        override fun onCaptureSuccess(image: ImageProxy) {
                            val buffer = image.planes[0].buffer
                            val bytes = ByteArray(buffer.remaining())
                            buffer.get(bytes)
                            image.close()
                            val saved = VaultCrypto.encryptToVault(
                                context, bytes, "IMG_${System.currentTimeMillis()}"
                            )
                            Toast.makeText(context, "Encrypted & secured", Toast.LENGTH_SHORT).show()

                            // Auto-upload only if the box is on, a token is set, AND
                            // at least one approved recipient exists to encrypt to.
                            val token = prefs.getString("yandex_token", "").orEmpty()
                            val recipients = RecipientStore.publicBundles(context)
                            if (prefs.getBoolean("auto_upload", false) &&
                                token.isNotBlank() && recipients.isNotEmpty()
                            ) {
                                scope.launch {
                                    YandexUploader.ensureFolder(token, "/PTI")
                                    val plain = VaultCrypto.decryptFromVault(context, saved)
                                    val sealed = HybridCrypto.encryptToMany(plain, recipients)
                                    YandexUploader.upload(
                                        token, "/PTI/${saved.nameWithoutExtension}.ptq", sealed
                                    )
                                }
                            }
                            onDone()
                        }

                        override fun onError(exc: ImageCaptureException) {
                            Toast.makeText(
                                context, "Capture failed: ${exc.message}", Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                )
            },
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(32.dp)
        ) { Text("Capture") }
    }
}

@Composable
fun RecipientsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current

    var entries by remember { mutableStateOf(RecipientStore.list(context)) }
    var newLabel by remember { mutableStateOf("") }
    var privateKeyToShow by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
    ) {
        Text("Who can access the evidence", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(
            "Add each trusted person. They receive a private key — give it to them " +
                "privately (in person or a secure message). Only people on this list can " +
                "ever decrypt the evidence. Remove someone to revoke their future access."
        )

        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = newLabel,
            onValueChange = { newLabel = it },
            label = { Text("Name (e.g. Mom, Lawyer)") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        Button(
            modifier = Modifier.fillMaxWidth(),
            onClick = {
                val recipient = HybridCrypto.generateRecipient()
                RecipientStore.add(context, newLabel, HybridCrypto.exportPublicKeys(recipient))
                entries = RecipientStore.list(context)
                newLabel = ""
                privateKeyToShow = HybridCrypto.exportPrivateKeys(recipient)
            }
        ) { Text("Add person & generate their key") }

        Spacer(Modifier.height(24.dp))
        if (entries.isEmpty()) {
            Text("No one added yet.")
        } else {
            entries.forEach { entry ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(entry.label, modifier = Modifier.weight(1f))
                    TextButton(onClick = {
                        RecipientStore.remove(context, entry.publicBundle)
                        entries = RecipientStore.list(context)
                    }) { Text("Revoke") }
                }
            }
        }

        Spacer(Modifier.height(24.dp))
        OutlinedButton(onClick = onBack) { Text("Done") }
    }

    val keyText = privateKeyToShow
    if (keyText != null) {
        AlertDialog(
            onDismissRequest = { privateKeyToShow = null },
            title = { Text("Private key — give this to the person") },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    Text(
                        "Send this privately to the person. They need it to view the " +
                            "evidence. Never post it publicly. It is not stored anywhere else."
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(keyText, style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    clipboard.setText(AnnotatedString(keyText))
                    Toast.makeText(context, "Key copied", Toast.LENGTH_SHORT).show()
                }) { Text("Copy") }
            },
            dismissButton = {
                TextButton(onClick = { privateKeyToShow = null }) { Text("Close") }
            }
        )
    }
}
