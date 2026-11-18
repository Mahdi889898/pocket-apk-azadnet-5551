package com.example.network

import com.example.data.AzadNetSettings
import com.example.data.BypassMode
import com.example.data.ProbeTargetResult
import com.example.data.VpnStatus
import com.example.vpn.DnsPacketCodec
import com.example.vpn.DohResolver
import com.example.vpn.TunnelRuntimeState
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

class ConnectivityProbe {

  suspend fun runFullProbe(settings: AzadNetSettings): List<ProbeTargetResult> = coroutineScope {
    val runtime = TunnelRuntimeState.stats.value
    val useActiveProxy = runtime.status == VpnStatus.CONNECTED &&
      runtime.localHttpProxyPort > 0 &&
      settings.bypassMode != BypassMode.DOH_ONLY

    val dohResolver = DohResolver(
      dohUrl = settings.effectiveDohUrl(),
      bootstrapIp = settings.dohProvider.bootstrapIp,
      protectSocket = { true },
    )

    val probeClientBuilder = OkHttpClient.Builder()
      .connectTimeout(7, TimeUnit.SECONDS)
      .readTimeout(7, TimeUnit.SECONDS)
      .followRedirects(false)

    if (useActiveProxy) {
      probeClientBuilder.proxy(
        Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", runtime.localHttpProxyPort))
      )
    } else if (runtime.status == VpnStatus.CONNECTED) {
      probeClientBuilder.dns(object : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
          val resolved = dohResolver.resolveHostAddresses(hostname)
          return resolved.ifEmpty { Dns.SYSTEM.lookup(hostname) }
        }
      })
    }

    val probeClient = probeClientBuilder.build()
    val directClient = OkHttpClient.Builder()
      .connectTimeout(7, TimeUnit.SECONDS)
      .readTimeout(7, TimeUnit.SECONDS)
      .followRedirects(false)
      .build()

    val dohTarget = ProbeSpec(
      id = "doh",
      titleFa = "سرویس DNS رمزنگاری‌شده (${settings.dohProvider.titleFa})",
      endpoint = settings.effectiveDohUrl(),
      isDoh = true,
    )

    val targets = listOf(
      dohTarget,
      ProbeSpec("tg_api", "تلگرام API", "https://api.telegram.org", false),
      ProbeSpec("tg_web", "تلگرام وب", "https://web.telegram.org", false),
      ProbeSpec("ig_web", "اینستاگرام وب", "https://www.instagram.com", false),
      ProbeSpec("ig_api", "اینستاگرام موبایل API", "https://i.instagram.com", false),
    )

    val routeLabel = when {
      useActiveProxy -> "از طریق تونل آزادنت"
      runtime.status == VpnStatus.CONNECTED -> "از طریق DoH آزادنت"
      else -> "مستقیم (تونل خاموش)"
    }

    targets.map { spec ->
      async(Dispatchers.IO) {
        val clientToUse = if (spec.isDoh) directClient else probeClient
        probeSingle(clientToUse, spec, routeLabel)
      }
    }.awaitAll()
  }

  private suspend fun probeSingle(
    client: OkHttpClient,
    spec: ProbeSpec,
    routeLabel: String,
  ): ProbeTargetResult = withContext(Dispatchers.IO) {
    val startMs = System.currentTimeMillis()
    try {
      val request = if (spec.isDoh) {
        val dnsQuery = DnsPacketCodec.buildDnsQuery("api.telegram.org", queryType = 1)
        Request.Builder()
          .url(spec.endpoint)
          .post(dnsQuery.toRequestBody("application/dns-message".toMediaType()))
          .header("Accept", "application/dns-message")
          .build()
      } else {
        Request.Builder()
          .url(spec.endpoint)
          .head()
          .header("User-Agent", "Mozilla/5.0 (Android)")
          .build()
      }

      client.newCall(request).execute().use { response ->
        val elapsed = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)
        val ok = response.code in 200..499
        val detail = if (spec.isDoh) {
          val bytes = response.body?.bytes()
          val ips = if (bytes != null) DnsPacketCodec.extractResolvedAddresses(bytes) else emptyList()
          if (ips.isNotEmpty()) "پاسخ DoH: ${ips.first()}" else "کد HTTP ${response.code}"
        } else {
          "کد ${response.code} • $routeLabel"
        }
        ProbeTargetResult(
          id = spec.id,
          titleFa = spec.titleFa,
          endpoint = spec.endpoint,
          isSuccess = ok,
          latencyMs = elapsed,
          detailFa = detail,
        )
      }
    } catch (e: Exception) {
      val elapsed = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)
      ProbeTargetResult(
        id = spec.id,
        titleFa = spec.titleFa,
        endpoint = spec.endpoint,
        isSuccess = false,
        latencyMs = elapsed,
        detailFa = (e.javaClass.simpleName + ": " + (e.message?.take(50) ?: "خطای شبکه")),
      )
    }
  }

  private data class ProbeSpec(
    val id: String,
    val titleFa: String,
    val endpoint: String,
    val isDoh: Boolean,
  )
}
