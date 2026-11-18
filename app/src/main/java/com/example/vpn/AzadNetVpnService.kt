package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.data.AzadNetSettings
import com.example.data.BypassMode
import com.example.data.InstalledAppsInspector
import com.example.data.RoutingScope
import com.example.data.SettingsRepository
import com.example.data.VpnStatus
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class AzadNetVpnService : VpnService() {

  companion object {
    const val ACTION_START = "com.example.vpn.ACTION_START"
    const val ACTION_STOP = "com.example.vpn.ACTION_STOP"
    private const val NOTIFICATION_CHANNEL_ID = "azadnet_vpn_channel"
    private const val NOTIFICATION_ID = 7001
    private const val VIRTUAL_TUN_IP = "10.120.0.1"
    private const val VIRTUAL_DNS_IP = "10.120.0.2"
    private const val VIRTUAL_TUN_IP6 = "fd00:120::1"

    fun startIntent(context: Context): Intent =
      Intent(context, AzadNetVpnService::class.java).setAction(ACTION_START)

    fun stopIntent(context: Context): Intent =
      Intent(context, AzadNetVpnService::class.java).setAction(ACTION_STOP)
  }

  private val running = AtomicBoolean(false)
  private val stateLock = Any()
  private var serviceScope: CoroutineScope? = null
  private var tunInterface: ParcelFileDescriptor? = null
  private var localProxyServer: LocalProxyServer? = null
  private var tunForwarder: TunPacketForwarder? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_STOP -> {
        stopTunnel()
        stopSelf()
        return START_NOT_STICKY
      }
      ACTION_START, null -> {
        startTunnel()
        return START_STICKY
      }
      else -> return START_NOT_STICKY
    }
  }

  private fun startTunnel() {
    synchronized(stateLock) {
      if (running.getAndSet(true)) return
      TunnelRuntimeState.setStatus(VpnStatus.CONNECTING)
      promoteToForeground()
      serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }

    serviceScope?.launch {
      try {
        val settings = SettingsRepository(applicationContext).getCurrentSettings()
        val resolver = DohResolver(
          dohUrl = settings.effectiveDohUrl(),
          bootstrapIp = settings.dohProvider.bootstrapIp,
          protectSocket = { sock -> protect(sock) },
        )

        val proxyServer = LocalProxyServer(
          settings = settings,
          dohResolver = resolver,
          protectSocket = { sock -> protect(sock) },
        )
        val (httpPort, socksPort) = proxyServer.start()
        synchronized(stateLock) {
          if (!running.get()) {
            proxyServer.stop()
            return@launch
          }
          localProxyServer = proxyServer
        }

        val (builder, routedPkgs, usedFallback) = buildVpnInterface(settings, httpPort)
        val tun = builder.establish()
          ?: throw IllegalStateException("دسترسی VPN توسط سیستم تایید نشد")

        synchronized(stateLock) {
          if (!running.get()) {
            runCatching { tun.close() }
            return@launch
          }
          tunInterface = tun
        }

        val tunOutput = FileOutputStream(tun.fileDescriptor)
        val forwarder = TunPacketForwarder(
          settings = settings,
          dohResolver = resolver,
          tunOutput = tunOutput,
          protectSocket = { sock -> protect(sock) },
          protectDatagram = { channel -> protect(channel.socket()) },
        )
        synchronized(stateLock) {
          if (!running.get()) {
            forwarder.stop()
            return@launch
          }
          tunForwarder = forwarder
        }

        TunnelRuntimeState.setStatus(
          status = VpnStatus.CONNECTED,
          localHttpPort = httpPort,
          localSocksPort = socksPort,
          routedPackages = routedPkgs,
          usedFullDeviceFallback = usedFallback,
          lastError = null,
        )

        runPacketLoop(tun, forwarder)
      } catch (e: Exception) {
        TunnelRuntimeState.setStatus(
          status = VpnStatus.ERROR,
          lastError = e.message ?: "خطا در راه‌اندازی تونل",
        )
        stopTunnel(keepErrorState = true)
        stopSelf()
      }
    }
  }

  private fun buildVpnInterface(
    settings: AzadNetSettings,
    httpPort: Int,
  ): Triple<Builder, List<String>, Boolean> {
    val builder = Builder()
      .setSession("AzadNet")
      .setMtu(1500)
      .addAddress(VIRTUAL_TUN_IP, 30)
      .addDnsServer(VIRTUAL_DNS_IP)
      .addRoute("0.0.0.0", 0)
      // Capture IPv6 default route to prevent IPv6 ISP leaks while returning IPv4 priority on DNS
      .addAddress(VIRTUAL_TUN_IP6, 126)
      .addRoute("::", 0)
      .setBlocking(true)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && httpPort > 0 && settings.bypassMode != BypassMode.DOH_ONLY) {
      builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", httpPort))
    }

    val routedPackages = mutableListOf<String>()
    var usedFallback = false

    if (settings.routingScope == RoutingScope.SPLIT_TELEGRAM_INSTAGRAM) {
      val candidates = mutableListOf<String>()
      if (settings.includeTelegram) {
        candidates.addAll(InstalledAppsInspector.inspectTelegram(applicationContext).installedPackages)
      }
      if (settings.includeInstagram) {
        candidates.addAll(InstalledAppsInspector.inspectInstagram(applicationContext).installedPackages)
      }

      if (candidates.isNotEmpty()) {
        for (pkg in candidates.distinct()) {
          if (pkg != packageName) {
            runCatching {
              builder.addAllowedApplication(pkg)
              routedPackages.add(pkg)
            }
          }
        }
      } else {
        usedFallback = true
        runCatching { builder.addDisallowedApplication(packageName) }
      }
    } else {
      runCatching { builder.addDisallowedApplication(packageName) }
    }

    return Triple(builder, routedPackages, usedFallback)
  }

  private fun runPacketLoop(tun: ParcelFileDescriptor, forwarder: TunPacketForwarder) {
    val input = FileInputStream(tun.fileDescriptor)
    val buffer = ByteArray(32767)

    while (running.get()) {
      val length = try {
        input.read(buffer)
      } catch (_: Exception) {
        break
      }
      if (length <= 0) continue
      forwarder.handlePacket(buffer, length)
    }
  }

  private fun promoteToForeground() {
    val nm = getSystemService(NotificationManager::class.java)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val channel = NotificationChannel(
        NOTIFICATION_CHANNEL_ID,
        getString(R.string.vpn_notif_channel_name),
        NotificationManager.IMPORTANCE_LOW,
      ).apply {
        description = getString(R.string.vpn_notif_channel_desc)
      }
      nm.createNotificationChannel(channel)
    }

    val openAppIntent = PendingIntent.getActivity(
      this,
      1,
      Intent(this, MainActivity::class.java),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    val stopPendingIntent = PendingIntent.getService(
      this,
      2,
      stopIntent(this),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    val notification: Notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
      .setSmallIcon(R.drawable.ic_vpn_shield)
      .setContentTitle(getString(R.string.vpn_notif_title))
      .setContentText(getString(R.string.app_tagline))
      .setOngoing(true)
      .setContentIntent(openAppIntent)
      .addAction(0, getString(R.string.vpn_notif_disconnect), stopPendingIntent)
      .build()

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
    } else {
      startForeground(NOTIFICATION_ID, notification)
    }
  }

  private fun stopTunnel(keepErrorState: Boolean = false) {
    synchronized(stateLock) {
      running.set(false)
      runCatching { tunForwarder?.stop() }
      tunForwarder = null
      runCatching { tunInterface?.close() }
      tunInterface = null
      runCatching { localProxyServer?.stop() }
      localProxyServer = null
      serviceScope?.cancel()
      serviceScope = null
    }
    if (!keepErrorState) {
      TunnelRuntimeState.resetCountersOnStop()
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
    } else {
      @Suppress("DEPRECATION")
      runCatching { stopForeground(true) }
    }
  }

  override fun onRevoke() {
    stopTunnel()
    stopSelf()
    super.onRevoke()
  }

  override fun onDestroy() {
    stopTunnel()
    super.onDestroy()
  }
}
