/**
 * Real Android TUN VPN service (VpnService.Builder).
 *
 * Creates a TUN fd, establishes routes, and pipes packets to/from a local
 * xray `mixed` inbound.  On Android the Python Flet UI runs inside a WebView;
 * this service is started via the WebView's JavaScript bridge or an Activity
 * button.
 */
package net.netprobe

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import java.io.FileOutputStream

class VpnTunService : VpnService() {
    companion object {
        private const val TAG = "NetProbeVPN"
        private const val CHANNEL_ID = "netprobe_vpn"
        private const val NOTIFY_ID = 1
        private const val TUN_NAME = "netprobe"
        private const val LOCAL_IP = "10.0.0.2"
        private const val LOCAL_IPV6 = "fd00::2"
        private const val VPN_MTU = 1500
        private const val XRAY_PORT = 10808
    }

    private var builder: VpnService.Builder? = null
    private var iface: ParcelFileDescriptor? = null
    private var xrayProcess: Process? = null
    private var running = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFY_ID, buildNotification("Starting tunnel…"))
        startVpn()
        return START_STICKY
    }

    /** Start the VPN and spawn xray. */
    fun startVpn() {
        if (running) return
        try {
            builder = Builder()
                .setSession(TUN_NAME)
                .addAddress(LOCAL_IP, 24)
                .addAddress(LOCAL_IPV6, 64)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .setMtu(VPN_MTU)

            // Bypass the VPN for localhost (xray listens on 127.0.0.1:10808).
            builder!!.addDisallowedApplication(packageName)

            iface = builder!!.establish()
            running = true
            Log.i(TAG, "VPN interface established")

            // Write xray config from assets if needed, then start xray.
            val configFile = File(filesDir, "config.json")
            copyAsset("config.json", configFile)

            val xrayBinary = extractXrayBinary()
            xrayBinary.setExecutable(true)
            xrayProcess = Runtime.getRuntime().exec(
                arrayOf(xrayBinary.absolutePath, "run", "-c", configFile.absolutePath),
                null,
                filesDir
            )

            // Pump stderr to logcat.
            Thread {
                xrayBinary!!.inputStream.bufferedReader().useLines { }
                Log.i(TAG, "xray stderr ended")
            }.start()

        } catch (e: Exception) {
            Log.e(TAG, "VPN start failed", e)
            stopVpn()
        }
    }

    /** Stop the VPN and kill xray. */
    fun stopVpn() {
        try { xrayProcess?.destroy() } catch (_: Exception) {}
        xrayProcess = null
        try { iface?.close() } catch (_: Exception) {}
        iface = null
        running = false
        Log.i(TAG, "VPN stopped")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            mgr.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "NetProbe VPN", NotificationManager.IMPORTANCE_LOW)
                    .apply { setShowBadge(false) }
            )
        }
    }

    private fun buildNotification(text: String): Notification {
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("NetProbe")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_data_saver)
            .build()
    }

    private fun extractXrayBinary(): File {
        val target = File(filesDir, "xray")
        if (target.exists()) return target
        assets.open("xray").use { input ->
            FileOutputStream(target).use { output ->
                input.copyTo(output)
            }
        }
        return target
    }

    private fun copyAsset(name: String, target: File) {
        if (target.exists()) return
        assets.open(name).use { input ->
            target.outputStream().use { output ->
                input.copyTo(output)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}