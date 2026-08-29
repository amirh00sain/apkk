package net.netprobe

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationManagerCompat

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private val VPN_REQUEST = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // On Android 13+ request POST_NOTIFICATIONS for the VPN foreground service.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val missing = NotificationManagerCompat.from(this).areNotificationsEnabled().not()
            if (missing) {
                requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 2001)
            }
        }

        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            webViewClient = WebViewClient()
            addJavascriptInterface(VpnBridge(), "VpnBridge")
        }
        setContentView(webView)

        // Serve the minimal HTML UI from assets.
        webView.loadUrl("file:///android_asset/index.html")
    }

    private inner class VpnBridge {
        @JavascriptInterface
        fun connect() {
            // Request VPN permission from the system, then start the service.
            val intent = VpnService.prepare(this@MainActivity)
            if (intent != null) {
                startActivityForResult(intent, VPN_REQUEST)
            } else {
                onVpnPermissionGranted()
            }
        }

        @JavascriptInterface
        fun disconnect() {
            val svc = Intent(this@MainActivity, VpnTunService::class.java)
            stopService(svc)
            notifyUi("disconnected")
        }
    }

    @Deprecated("Use activity result callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST && resultCode == Activity.RESULT_OK) {
            onVpnPermissionGranted()
        } else {
            notifyUi("permission-denied")
        }
    }

    private fun onVpnPermissionGranted() {
        val svc = Intent(this, VpnTunService::class.java)
        startForegroundService(svc)
        notifyUi("connected")
    }

    private fun notifyUi(state: String) {
        webView.post {
            webView.evaluateJavascript("onVpnState('$state')", null)
        }
    }
}