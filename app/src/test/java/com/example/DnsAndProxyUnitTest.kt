package com.example

import com.example.data.AppCategory
import com.example.data.AzadNetSettings
import com.example.data.BypassMode
import com.example.data.InstalledAppsInspector
import com.example.data.TelegramProxyParser
import com.example.vpn.DnsPacketCodec
import com.example.vpn.DohResolver
import com.example.vpn.LocalProxyServer
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class DnsAndProxyUnitTest {

  @Test
  fun `dns query roundtrip wraps and parses ip udp packet`() {
    val dnsQuery = DnsPacketCodec.buildDnsQuery("api.telegram.org", queryType = 1, transactionId = 0x4242)
    val ipLen = 20 + 8 + dnsQuery.size
    val packet = ByteArray(ipLen)
    packet[0] = 0x45.toByte()
    packet[2] = ((ipLen ushr 8) and 0xFF).toByte()
    packet[3] = (ipLen and 0xFF).toByte()
    packet[9] = 17.toByte()
    packet[12] = 10; packet[13] = 120; packet[14] = 0; packet[15] = 1
    packet[16] = 10; packet[17] = 120; packet[18] = 0; packet[19] = 2
    packet[20] = (51234 ushr 8).toByte(); packet[21] = (51234 and 0xFF).toByte()
    packet[22] = 0; packet[23] = 53
    val udpLen = 8 + dnsQuery.size
    packet[24] = ((udpLen ushr 8) and 0xFF).toByte(); packet[25] = (udpLen and 0xFF).toByte()
    System.arraycopy(dnsQuery, 0, packet, 28, dnsQuery.size)

    val parsed = DnsPacketCodec.parseIpUdpDns(packet, packet.size)
    assertNotNull(parsed)
    assertEquals("api.telegram.org", parsed!!.queryDomain)
    assertEquals("A", parsed.queryTypeName)
    assertEquals(0x4242, parsed.transactionId)

    val servFail = DnsPacketCodec.buildServFailResponse(parsed.dnsPayload)
    val responsePacket = DnsPacketCodec.buildIpUdpDnsResponse(parsed, servFail)
    assertEquals(10.toByte(), responsePacket[12])
    assertEquals(2.toByte(), responsePacket[15])
    assertEquals(1.toByte(), responsePacket[19])
    assertEquals(53, ((responsePacket[20].toInt() and 0xFF) shl 8) or (responsePacket[21].toInt() and 0xFF))

    val noError = DnsPacketCodec.buildEmptyNoErrorResponse(parsed.dnsPayload)
    assertEquals(0x80.toByte(), noError[3])
    assertEquals(0.toByte(), noError[7])
  }

  @Test
  fun `tcp packet builder constructs valid ipv4 tcp header with mss`() {
    val srcIp = byteArrayOf(149.toByte(), 154.toByte(), 167.toByte(), 50)
    val dstIp = byteArrayOf(10, 120, 0, 1)
    val pkt = DnsPacketCodec.buildIpTcpPacket(
      srcIp = srcIp,
      dstIp = dstIp,
      srcPort = 443,
      dstPort = 55000,
      seqNum = 123456L,
      ackNum = 789012L,
      flags = 0x12, // SYN | ACK
      mss = 1360,
    )
    assertEquals(44, pkt.size) // 20 IP + 24 TCP
    assertEquals(6, pkt[9].toInt() and 0xFF)
    assertEquals(443, DnsPacketCodec.readUInt16(pkt, 20))
    assertEquals(55000, DnsPacketCodec.readUInt16(pkt, 22))
    assertEquals(123456L, DnsPacketCodec.readUInt32(pkt, 24))
    assertEquals(789012L, DnsPacketCodec.readUInt32(pkt, 28))
    assertEquals(0x12, pkt[33].toInt() and 0xFF)
    assertEquals(1360, DnsPacketCodec.readUInt16(pkt, 42))
  }

  @Test
  fun `local proxy server relays http connect and socks5 over loopback`() {
    val echoServer = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
    val echoThread = thread(isDaemon = true) {
      while (!echoServer.isClosed) {
        try {
          val s = echoServer.accept()
          thread(isDaemon = true) {
            s.use { client ->
              val bytes = ByteArray(1024)
              while (true) {
                val n = client.getInputStream().read(bytes)
                if (n <= 0) break
                client.getOutputStream().write(bytes, 0, n)
                client.getOutputStream().flush()
              }
            }
          }
        } catch (_: Exception) {
          break
        }
      }
    }

    val settings = AzadNetSettings(bypassMode = BypassMode.DOH_PLUS_ANTI_DPI, tlsChunkSize = 3)
    val doh = DohResolver(settings.effectiveDohUrl(), settings.dohProvider.bootstrapIp) { true }
    val proxy = LocalProxyServer(settings, doh) { true }
    val (httpPort, socksPort) = proxy.start()

    try {
      // Test HTTP CONNECT
      Socket("127.0.0.1", httpPort).use { client ->
        client.soTimeout = 3000
        val out = client.getOutputStream()
        out.write("CONNECT 127.0.0.1:${echoServer.localPort} HTTP/1.1\r\nHost: 127.0.0.1:${echoServer.localPort}\r\n\r\n".toByteArray())
        out.flush()
        val reader = BufferedReader(InputStreamReader(client.getInputStream()))
        val statusLine = reader.readLine()
        assertTrue(statusLine.contains("200"))
        reader.readLine() // blank line
        // Send TLS ClientHello-like prefix to exercise anti-DPI split path
        val tlsLike = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x41, 0x42, 0x43, 0x44)
        out.write(tlsLike)
        out.flush()
        val resp = ByteArray(tlsLike.size)
        var readTotal = 0
        while (readTotal < resp.size) {
          val r = client.getInputStream().read(resp, readTotal, resp.size - readTotal)
          if (r <= 0) break
          readTotal += r
        }
        assertEquals(tlsLike.size, readTotal)
      }

      // Test SOCKS5 CONNECT
      Socket("127.0.0.1", socksPort).use { client ->
        client.soTimeout = 3000
        val out = client.getOutputStream()
        val inp = client.getInputStream()
        out.write(byteArrayOf(0x05, 0x01, 0x00))
        out.flush()
        val greet = ByteArray(2)
        assertEquals(2, inp.read(greet))
        assertEquals(0x00.toByte(), greet[1])

        val port = echoServer.localPort
        out.write(
          byteArrayOf(
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            ((port ushr 8) and 0xFF).toByte(), (port and 0xFF).toByte(),
          )
        )
        out.flush()
        val rep = ByteArray(10)
        assertEquals(10, inp.read(rep))
        assertEquals(0x00.toByte(), rep[1])
      }
    } finally {
      proxy.stop()
      runCatching { echoServer.close() }
      echoThread.interrupt()
    }
  }

  @Test
  fun `telegram proxy parser parses mtproto and socks links`() {
    val mtproto = TelegramProxyParser.parse("https://t.me/proxy?server=1.2.3.4&port=443&secret=dd0011223344")
    assertNotNull(mtproto)
    assertTrue(mtproto!!.isMtproto)
    assertEquals("1.2.3.4", mtproto.server)
    assertEquals(443, mtproto.port)
    assertEquals("dd0011223344", mtproto.secret)

    val socks = TelegramProxyParser.parse("tg://socks?server=127.0.0.1&port=10808")
    assertNotNull(socks)
    assertEquals(false, socks!!.isMtproto)
    assertEquals(10808, socks.port)

    assertNull(TelegramProxyParser.parse("https://example.com/notproxy"))
  }

  @Test
  fun `domain classifier distinguishes telegram and instagram`() {
    assertEquals(AppCategory.TELEGRAM, InstalledAppsInspector.classifyDomain("api.telegram.org"))
    assertEquals(AppCategory.INSTAGRAM, InstalledAppsInspector.classifyDomain("i.instagram.com"))
    assertEquals(AppCategory.INSTAGRAM, InstalledAppsInspector.classifyDomain("scontent.cdninstagram.com"))
    assertEquals(AppCategory.SYSTEM, InstalledAppsInspector.classifyDomain("example.com"))
  }
}
