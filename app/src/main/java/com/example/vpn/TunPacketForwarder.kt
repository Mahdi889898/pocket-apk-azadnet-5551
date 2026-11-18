package com.example.vpn

import android.util.Base64
import com.example.data.AzadNetSettings
import com.example.data.BypassMode
import com.example.data.DnsLogEntry
import com.example.data.InstalledAppsInspector
import com.example.data.UpstreamProxyType
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class TunPacketForwarder(
  private val settings: AzadNetSettings,
  private val dohResolver: DohResolver,
  private val tunOutput: FileOutputStream,
  private val protectSocket: (Socket) -> Boolean,
  private val protectDatagram: (DatagramChannel) -> Boolean,
) {
  companion object {
    private const val TCP_FIN = 0x01
    private const val TCP_SYN = 0x02
    private const val TCP_RST = 0x04
    private const val TCP_PSH = 0x08
    private const val TCP_ACK = 0x10
    private const val MAX_TCP_SEGMENT = 1360
  }

  private data class SessionKey(
    val srcIp: Int,
    val srcPort: Int,
    val dstIp: Int,
    val dstPort: Int,
  )

  private inner class TcpSession(
    val key: SessionKey,
    val clientIpBytes: ByteArray,
    val remoteIpBytes: ByteArray,
    val clientPort: Int,
    val remotePort: Int,
    @Volatile var theirNextSeq: Long,
    @Volatile var myNextSeq: Long,
  ) {
    val lock = Any()
    val outboundChannel = kotlinx.coroutines.channels.Channel<ByteArray>(kotlinx.coroutines.channels.Channel.UNLIMITED)
    @Volatile var socket: Socket? = null
    @Volatile var established: Boolean = false
    @Volatile var closed: Boolean = false
    @Volatile var isFirstPayload: Boolean = true
    @Volatile var finSentToTun: Boolean = false

    fun closeQuietly() {
      if (closed) return
      closed = true
      outboundChannel.close()
      runCatching { socket?.close() }
      tcpSessions.remove(key)
    }
  }

  private inner class UdpSession(
    val key: SessionKey,
    val clientIpBytes: ByteArray,
    val remoteIpBytes: ByteArray,
    val clientPort: Int,
    val remotePort: Int,
    val channel: DatagramChannel,
  ) {
    @Volatile var lastActiveMs: Long = System.currentTimeMillis()
  }

  private val running = AtomicBoolean(true)
  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private val writeLock = Any()
  private val tcpSessions = ConcurrentHashMap<SessionKey, TcpSession>()
  private val udpSessions = ConcurrentHashMap<SessionKey, UdpSession>()

  init {
    scope.launch {
      while (isActive && running.get()) {
        delay(20_000L)
        val cutoff = System.currentTimeMillis() - 45_000L
        udpSessions.entries.removeIf { (_, session) ->
          if (session.lastActiveMs < cutoff) {
            runCatching { session.channel.close() }
            true
          } else {
            false
          }
        }
      }
    }
  }

  fun handlePacket(packet: ByteArray, length: Int) {
    if (!running.get() || length < 20) return
    val version = (packet[0].toInt() ushr 4) and 0x0F
    if (version != 4) return

    val ihl = (packet[0].toInt() and 0x0F) * 4
    if (ihl < 20 || length < ihl) return

    val totalLength = minOf(length, DnsPacketCodec.readUInt16(packet, 2))
    val protocol = packet[9].toInt() and 0xFF

    when (protocol) {
      17 -> handleUdpPacket(packet, ihl, totalLength)
      6 -> handleTcpPacket(packet, ihl, totalLength)
    }
  }

  private fun handleUdpPacket(packet: ByteArray, ihl: Int, totalLength: Int) {
    if (totalLength < ihl + 8) return
    val dstPort = DnsPacketCodec.readUInt16(packet, ihl + 2)

    if (dstPort == 53) {
      val parsedDns = DnsPacketCodec.parseIpUdpDns(packet, totalLength) ?: return
      TunnelRuntimeState.addTraffic(bytesInDelta = 0L, bytesOutDelta = totalLength.toLong())
      handleDnsQuery(parsedDns)
      return
    }

    // Drop QUIC/HTTP3 (UDP 443) so Instagram & browsers fall back cleanly to TCP/443 for Anti-DPI / Proxy.
    if (dstPort == 443) return

    // In DOH_ONLY mode, let's still forward general UDP cleanly so voice/STUN works.
    val srcPort = DnsPacketCodec.readUInt16(packet, ihl)
    val udpLen = DnsPacketCodec.readUInt16(packet, ihl + 4)
    val payloadStart = ihl + 8
    val payloadEnd = minOf(totalLength, ihl + udpLen)
    if (payloadEnd <= payloadStart) return

    val srcIpBytes = packet.copyOfRange(12, 16)
    val dstIpBytes = packet.copyOfRange(16, 20)
    val payload = packet.copyOfRange(payloadStart, payloadEnd)

    val key = SessionKey(ipToInt(srcIpBytes), srcPort, ipToInt(dstIpBytes), dstPort)
    val existing = udpSessions[key]
    val session = existing ?: createUdpSession(key, srcIpBytes, dstIpBytes, srcPort, dstPort) ?: return

    session.lastActiveMs = System.currentTimeMillis()
    scope.launch {
      runCatching {
        session.channel.write(ByteBuffer.wrap(payload))
        TunnelRuntimeState.addTraffic(bytesInDelta = 0L, bytesOutDelta = payload.size.toLong())
      }
    }
  }

  private fun createUdpSession(
    key: SessionKey,
    srcIpBytes: ByteArray,
    dstIpBytes: ByteArray,
    srcPort: Int,
    dstPort: Int,
  ): UdpSession? {
    return try {
      val channel = DatagramChannel.open()
      protectDatagram(channel)
      channel.connect(InetSocketAddress(InetAddress.getByAddress(dstIpBytes), dstPort))
      val session = UdpSession(key, srcIpBytes, dstIpBytes, srcPort, dstPort, channel)
      udpSessions[key] = session

      scope.launch {
        val buf = ByteBuffer.allocate(4096)
        try {
          while (running.get() && channel.isOpen) {
            buf.clear()
            val read = channel.read(buf)
            if (read <= 0) break
            session.lastActiveMs = System.currentTimeMillis()
            val respPayload = ByteArray(read)
            buf.flip()
            buf.get(respPayload)
            val ipUdp = DnsPacketCodec.buildIpUdpPacket(
              srcIp = session.remoteIpBytes,
              dstIp = session.clientIpBytes,
              srcPort = session.remotePort,
              dstPort = session.clientPort,
              ipId = Random.nextInt(1, 65535),
              payload = respPayload,
            )
            writeTunPacket(ipUdp)
            TunnelRuntimeState.addTraffic(bytesInDelta = ipUdp.size.toLong(), bytesOutDelta = 0L)
          }
        } catch (_: Exception) {
        } finally {
          udpSessions.remove(key)
          runCatching { channel.close() }
        }
      }
      session
    } catch (_: Exception) {
      null
    }
  }

  private fun handleDnsQuery(parsed: ParsedDnsPacket) {
    scope.launch {
      val startMs = System.currentTimeMillis()
      var success = true
      var resolvedSummary = ""

      val responseDns: ByteArray = if (parsed.queryTypeCode == 28) {
        // IPv4-only TUN: return empty NOERROR for AAAA so apps connect immediately via IPv4 without IPv6 leak or Happy Eyeballs delay.
        resolvedSummary = "IPv4 اولویت دارد"
        DnsPacketCodec.buildEmptyNoErrorResponse(parsed.dnsPayload)
      } else {
        try {
          val resolved = dohResolver.resolveRawDns(
            queryPayload = parsed.dnsPayload,
            domain = parsed.queryDomain,
            queryType = parsed.queryTypeName,
          )
          val ips = DnsPacketCodec.extractResolvedAddresses(resolved)
          resolvedSummary = if (ips.isNotEmpty()) ips.take(2).joinToString(", ") else "پاسخ DoH"
          resolved
        } catch (e: Exception) {
          success = false
          resolvedSummary = e.message ?: "خطای DoH"
          DnsPacketCodec.buildServFailResponse(parsed.dnsPayload)
        }
      }

      val elapsed = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)
      val ipResponse = DnsPacketCodec.buildIpUdpDnsResponse(parsed, responseDns)
      writeTunPacket(ipResponse)
      TunnelRuntimeState.addTraffic(bytesInDelta = ipResponse.size.toLong(), bytesOutDelta = 0L)

      if (parsed.queryDomain.isNotBlank() && parsed.queryTypeCode != 28) {
        TunnelRuntimeState.recordDnsQuery(
          DnsLogEntry(
            id = 0L,
            timestampMs = System.currentTimeMillis(),
            domain = parsed.queryDomain,
            queryType = parsed.queryTypeName,
            latencyMs = elapsed,
            resolvedSummary = resolvedSummary,
            isSuccess = success,
            category = InstalledAppsInspector.classifyDomain(parsed.queryDomain),
          )
        )
      }
    }
  }

  private fun handleTcpPacket(packet: ByteArray, ihl: Int, totalLength: Int) {
    if (totalLength < ihl + 20) return
    val srcIpBytes = packet.copyOfRange(12, 16)
    val dstIpBytes = packet.copyOfRange(16, 20)
    val srcPort = DnsPacketCodec.readUInt16(packet, ihl)
    val dstPort = DnsPacketCodec.readUInt16(packet, ihl + 2)
    val seqNum = DnsPacketCodec.readUInt32(packet, ihl + 4)
    val dataOffset = ((packet[ihl + 12].toInt() ushr 4) and 0x0F) * 4
    if (dataOffset < 20 || totalLength < ihl + dataOffset) return
    val flags = packet[ihl + 13].toInt() and 0xFF
    val payloadStart = ihl + dataOffset
    val payloadLen = (totalLength - payloadStart).coerceAtLeast(0)

    val key = SessionKey(ipToInt(srcIpBytes), srcPort, ipToInt(dstIpBytes), dstPort)

    if ((flags and TCP_RST) != 0) {
      tcpSessions[key]?.closeQuietly()
      return
    }

    if ((flags and TCP_SYN) != 0 && (flags and TCP_ACK) == 0) {
      // New TCP connection SYN
      tcpSessions[key]?.closeQuietly()
      val initialSeq = (Random.nextInt().toLong() and 0x3FFFFFFFL) + 10_000L
      val session = TcpSession(
        key = key,
        clientIpBytes = srcIpBytes,
        remoteIpBytes = dstIpBytes,
        clientPort = srcPort,
        remotePort = dstPort,
        theirNextSeq = u32(seqNum + 1L),
        myNextSeq = initialSeq,
      )
      tcpSessions[key] = session
      openRemoteTcpSession(session)
      return
    }

    val session = tcpSessions[key] ?: run {
      // Unknown session and not SYN -> send RST
      if ((flags and TCP_RST) == 0) {
        val ackNum = u32(seqNum + maxOf(1, payloadLen).toLong())
        val rst = DnsPacketCodec.buildIpTcpPacket(
          srcIp = dstIpBytes,
          dstIp = srcIpBytes,
          srcPort = dstPort,
          dstPort = srcPort,
          seqNum = 0L,
          ackNum = ackNum,
          flags = TCP_RST or TCP_ACK,
        )
        writeTunPacket(rst)
      }
      return
    }

    if (payloadLen > 0) {
      val payload = packet.copyOfRange(payloadStart, payloadStart + payloadLen)
      TunnelRuntimeState.addTraffic(bytesInDelta = 0L, bytesOutDelta = payloadLen.toLong())

      synchronized(session.lock) {
        if (seqNum == session.theirNextSeq) {
          session.theirNextSeq = u32(session.theirNextSeq + payloadLen.toLong())
          val ackPacket = DnsPacketCodec.buildIpTcpPacket(
            srcIp = session.remoteIpBytes,
            dstIp = session.clientIpBytes,
            srcPort = session.remotePort,
            dstPort = session.clientPort,
            seqNum = session.myNextSeq,
            ackNum = session.theirNextSeq,
            flags = TCP_ACK,
          )
          writeTunPacket(ackPacket)

          session.outboundChannel.trySend(payload)
        } else {
          // Retransmission or out-of-order: re-ACK expected sequence
          val ackPacket = DnsPacketCodec.buildIpTcpPacket(
            srcIp = session.remoteIpBytes,
            dstIp = session.clientIpBytes,
            srcPort = session.remotePort,
            dstPort = session.clientPort,
            seqNum = session.myNextSeq,
            ackNum = session.theirNextSeq,
            flags = TCP_ACK,
          )
          writeTunPacket(ackPacket)
        }
      }
    }

    if ((flags and TCP_FIN) != 0) {
      synchronized(session.lock) {
        session.theirNextSeq = u32(session.theirNextSeq + 1L)
        val finAck = DnsPacketCodec.buildIpTcpPacket(
          srcIp = session.remoteIpBytes,
          dstIp = session.clientIpBytes,
          srcPort = session.remotePort,
          dstPort = session.clientPort,
          seqNum = session.myNextSeq,
          ackNum = session.theirNextSeq,
          flags = TCP_ACK,
        )
        writeTunPacket(finAck)
        session.outboundChannel.close()
        if (session.finSentToTun) {
          session.closeQuietly()
        }
      }
    }
  }

  private fun openRemoteTcpSession(session: TcpSession) {
    scope.launch {
      val remoteIpStr = InetAddress.getByAddress(session.remoteIpBytes).hostAddress ?: run {
        sendRstAndClose(session)
        return@launch
      }

      val sock = connectOutboundSocket(remoteIpStr, session.remotePort)
      if (sock == null || session.closed || !running.get()) {
        runCatching { sock?.close() }
        sendRstAndClose(session)
        return@launch
      }

      synchronized(session.lock) {
        session.socket = sock
        session.established = true
        val synAck = DnsPacketCodec.buildIpTcpPacket(
          srcIp = session.remoteIpBytes,
          dstIp = session.clientIpBytes,
          srcPort = session.remotePort,
          dstPort = session.clientPort,
          seqNum = session.myNextSeq,
          ackNum = session.theirNextSeq,
          flags = TCP_SYN or TCP_ACK,
          mss = MAX_TCP_SEGMENT,
        )
        session.myNextSeq = u32(session.myNextSeq + 1L)
        writeTunPacket(synAck)
      }

      TunnelRuntimeState.incrementProxyConnection()

      // Strictly ordered FIFO writer coroutine for outbound TCP payloads
      val writerJob = scope.launch {
        try {
          val out = sock.getOutputStream()
          for (payload in session.outboundChannel) {
            if (session.closed || !running.get()) break
            val splitFirst = session.isFirstPayload &&
              settings.bypassMode == BypassMode.DOH_PLUS_ANTI_DPI &&
              isTlsClientHello(payload)
            session.isFirstPayload = false

            if (splitFirst) {
              val chunk = settings.tlsChunkSize.coerceIn(1, 32)
              val firstLen = minOf(chunk, payload.size)
              out.write(payload, 0, firstLen)
              out.flush()
              if (payload.size > firstLen) {
                delay(2L)
                val secondLen = minOf(chunk * 2, payload.size - firstLen)
                out.write(payload, firstLen, secondLen)
                out.flush()
                val rem = firstLen + secondLen
                if (payload.size > rem) {
                  out.write(payload, rem, payload.size - rem)
                  out.flush()
                }
              }
            } else {
              out.write(payload)
              out.flush()
            }
          }
          runCatching { sock.shutdownOutput() }
        } catch (_: Exception) {
          sendRstAndClose(session)
        }
      }

      val buffer = ByteArray(MAX_TCP_SEGMENT)
      try {
        val input = sock.getInputStream()
        while (running.get() && !session.closed && !sock.isClosed) {
          val read = input.read(buffer)
          if (read <= 0) break
          val chunk = buffer.copyOf(read)
          synchronized(session.lock) {
            val dataPacket = DnsPacketCodec.buildIpTcpPacket(
              srcIp = session.remoteIpBytes,
              dstIp = session.clientIpBytes,
              srcPort = session.remotePort,
              dstPort = session.clientPort,
              seqNum = session.myNextSeq,
              ackNum = session.theirNextSeq,
              flags = TCP_PSH or TCP_ACK,
              payload = chunk,
            )
            session.myNextSeq = u32(session.myNextSeq + read.toLong())
            writeTunPacket(dataPacket)
            TunnelRuntimeState.addTraffic(bytesInDelta = read.toLong(), bytesOutDelta = 0L)
          }
        }
        synchronized(session.lock) {
          if (!session.closed && !session.finSentToTun) {
            session.finSentToTun = true
            val finPacket = DnsPacketCodec.buildIpTcpPacket(
              srcIp = session.remoteIpBytes,
              dstIp = session.clientIpBytes,
              srcPort = session.remotePort,
              dstPort = session.clientPort,
              seqNum = session.myNextSeq,
              ackNum = session.theirNextSeq,
              flags = TCP_FIN or TCP_ACK,
            )
            session.myNextSeq = u32(session.myNextSeq + 1L)
            writeTunPacket(finPacket)
          }
        }
      } catch (_: Exception) {
        sendRstAndClose(session)
      } finally {
        writerJob.cancel()
        session.closeQuietly()
      }
    }
  }

  private fun connectOutboundSocket(targetHost: String, targetPort: Int): Socket? {
    if (settings.bypassMode == BypassMode.UPSTREAM_PROXY && settings.upstreamProxyHost.isNotBlank()) {
      return connectViaUpstreamProxy(targetHost, targetPort)
    }

    val sock = Socket()
    return try {
      protectSocket(sock)
      sock.tcpNoDelay = true
      sock.connect(InetSocketAddress(targetHost, targetPort), 7_000)
      sock
    } catch (_: Exception) {
      runCatching { sock.close() }
      null
    }
  }

  private fun connectViaUpstreamProxy(targetHost: String, targetPort: Int): Socket? {
    val proxyHost = settings.upstreamProxyHost.trim()
    val proxyPort = settings.upstreamProxyPort
    val proxyAddrs = dohResolver.resolveHostAddresses(proxyHost)
    if (proxyAddrs.isEmpty()) return null

    val sock = Socket()
    return try {
      protectSocket(sock)
      sock.tcpNoDelay = true
      sock.soTimeout = 15_000
      sock.connect(InetSocketAddress(proxyAddrs.first(), proxyPort), 8_000)

      val inStream = sock.getInputStream()
      val outStream = sock.getOutputStream()

      when (settings.upstreamProxyType) {
        UpstreamProxyType.SOCKS5 -> {
          val hasAuth = settings.upstreamProxyUser.isNotBlank()
          val greeting = if (hasAuth) byteArrayOf(0x05, 0x02, 0x00, 0x02) else byteArrayOf(0x05, 0x01, 0x00)
          outStream.write(greeting)
          outStream.flush()

          val methodChoice = ByteArray(2)
          if (!readFully(inStream, methodChoice) || methodChoice[0].toInt() != 0x05) {
            throw IOException("Invalid SOCKS5 greeting")
          }
          if (methodChoice[1].toInt() == 0x02) {
            val u = settings.upstreamProxyUser.toByteArray(Charsets.UTF_8)
            val p = settings.upstreamProxyPass.toByteArray(Charsets.UTF_8)
            val authReq = ByteArray(3 + u.size + p.size)
            authReq[0] = 0x01
            authReq[1] = u.size.toByte()
            System.arraycopy(u, 0, authReq, 2, u.size)
            authReq[2 + u.size] = p.size.toByte()
            System.arraycopy(p, 0, authReq, 3 + u.size, p.size)
            outStream.write(authReq)
            outStream.flush()
            val authResp = ByteArray(2)
            if (!readFully(inStream, authResp) || authResp[1].toInt() != 0x00) {
              throw IOException("SOCKS5 auth failed")
            }
          } else if (methodChoice[1].toInt() != 0x00) {
            throw IOException("SOCKS5 auth unsupported")
          }

          val ipBytes = InetAddress.getByName(targetHost).address
          val connectReq = ByteArray(6 + ipBytes.size)
          connectReq[0] = 0x05
          connectReq[1] = 0x01
          connectReq[2] = 0x00
          connectReq[3] = if (ipBytes.size == 4) 0x01 else 0x04
          System.arraycopy(ipBytes, 0, connectReq, 4, ipBytes.size)
          connectReq[4 + ipBytes.size] = ((targetPort ushr 8) and 0xFF).toByte()
          connectReq[5 + ipBytes.size] = (targetPort and 0xFF).toByte()
          outStream.write(connectReq)
          outStream.flush()

          val respHead = ByteArray(4)
          if (!readFully(inStream, respHead) || respHead[1].toInt() != 0x00) {
            throw IOException("SOCKS5 connect rejected")
          }
          when (respHead[3].toInt() and 0xFF) {
            0x01 -> readFully(inStream, ByteArray(6))
            0x04 -> readFully(inStream, ByteArray(18))
            0x03 -> {
              val dLen = inStream.read()
              if (dLen > 0) readFully(inStream, ByteArray(dLen + 2))
            }
          }
        }

        UpstreamProxyType.HTTP -> {
          val sb = StringBuilder()
          sb.append("CONNECT ").append(targetHost).append(':').append(targetPort).append(" HTTP/1.1\r\n")
          sb.append("Host: ").append(targetHost).append(':').append(targetPort).append("\r\n")
          if (settings.upstreamProxyUser.isNotBlank()) {
            val token = Base64.encodeToString(
              "${settings.upstreamProxyUser}:${settings.upstreamProxyPass}".toByteArray(Charsets.UTF_8),
              Base64.NO_WRAP,
            )
            sb.append("Proxy-Authorization: Basic ").append(token).append("\r\n")
          }
          sb.append("\r\n")
          outStream.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
          outStream.flush()
          val respHeaders = readHttpHeaders(inStream) ?: throw IOException("No HTTP proxy response")
          val firstLine = respHeaders.substringBefore("\r\n")
          if (!firstLine.contains(" 200")) {
            throw IOException("HTTP proxy failed: $firstLine")
          }
        }
      }

      sock.soTimeout = 0
      sock
    } catch (_: Exception) {
      runCatching { sock.close() }
      null
    }
  }

  private fun sendRstAndClose(session: TcpSession) {
    synchronized(session.lock) {
      if (!session.closed) {
        val rst = DnsPacketCodec.buildIpTcpPacket(
          srcIp = session.remoteIpBytes,
          dstIp = session.clientIpBytes,
          srcPort = session.remotePort,
          dstPort = session.clientPort,
          seqNum = session.myNextSeq,
          ackNum = session.theirNextSeq,
          flags = TCP_RST or TCP_ACK,
        )
        writeTunPacket(rst)
      }
      session.closeQuietly()
    }
  }

  private fun writeTunPacket(bytes: ByteArray) {
    synchronized(writeLock) {
      if (running.get()) {
        runCatching { tunOutput.write(bytes) }
      }
    }
  }

  private fun isTlsClientHello(buf: ByteArray): Boolean =
    buf.size >= 6 && buf[0] == 0x16.toByte() && buf[1] == 0x03.toByte() && buf[5] == 0x01.toByte()

  private fun readHttpHeaders(input: java.io.InputStream): String? {
    val sb = StringBuilder()
    var prev3 = 0; var prev2 = 0; var prev1 = 0; var count = 0
    while (count < 16_384) {
      val b = input.read()
      if (b < 0) return null
      sb.append(b.toChar())
      count++
      if (prev3 == '\r'.code && prev2 == '\n'.code && prev1 == '\r'.code && b == '\n'.code) {
        return sb.toString().removeSuffix("\r\n\r\n")
      }
      prev3 = prev2; prev2 = prev1; prev1 = b
    }
    return null
  }

  private fun readFully(input: java.io.InputStream, dest: ByteArray): Boolean {
    var offset = 0
    while (offset < dest.size) {
      val r = input.read(dest, offset, dest.size - offset)
      if (r < 0) return false
      offset += r
    }
    return true
  }

  private fun ipToInt(ip: ByteArray): Int =
    ((ip[0].toInt() and 0xFF) shl 24) or
      ((ip[1].toInt() and 0xFF) shl 16) or
      ((ip[2].toInt() and 0xFF) shl 8) or
      (ip[3].toInt() and 0xFF)

  private fun u32(v: Long): Long = v and 0xFFFFFFFFL

  fun stop() {
    running.set(false)
    tcpSessions.values.toList().forEach { it.closeQuietly() }
    tcpSessions.clear()
    udpSessions.values.toList().forEach { runCatching { it.channel.close() } }
    udpSessions.clear()
    scope.cancel()
  }
}
