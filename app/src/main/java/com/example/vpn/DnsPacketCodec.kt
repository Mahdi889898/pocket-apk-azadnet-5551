package com.example.vpn

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

data class ParsedDnsPacket(
  val srcIp: ByteArray,
  val dstIp: ByteArray,
  val srcPort: Int,
  val dstPort: Int,
  val ipId: Int,
  val dnsPayload: ByteArray,
  val transactionId: Int,
  val queryDomain: String,
  val queryTypeName: String,
  val queryTypeCode: Int,
)

object DnsPacketCodec {

  fun parseIpUdpDns(packet: ByteArray, length: Int): ParsedDnsPacket? {
    if (length < 20) return null
    val version = (packet[0].toInt() ushr 4) and 0x0F
    if (version != 4) return null

    val ihl = (packet[0].toInt() and 0x0F) * 4
    if (ihl < 20 || length < ihl + 8 + 12) return null

    val protocol = packet[9].toInt() and 0xFF
    if (protocol != 17) return null

    val totalLength = readUInt16(packet, 2)
    val effectiveLen = minOf(length, totalLength)
    if (effectiveLen < ihl + 8 + 12) return null

    val srcIp = packet.copyOfRange(12, 16)
    val dstIp = packet.copyOfRange(16, 20)
    val ipId = readUInt16(packet, 4)

    val srcPort = readUInt16(packet, ihl)
    val dstPort = readUInt16(packet, ihl + 2)
    if (dstPort != 53) return null

    val udpLen = readUInt16(packet, ihl + 4)
    val dnsStart = ihl + 8
    val dnsEnd = minOf(effectiveLen, ihl + udpLen)
    if (dnsEnd - dnsStart < 12) return null

    val dnsPayload = packet.copyOfRange(dnsStart, dnsEnd)
    val transactionId = readUInt16(dnsPayload, 0)
    val (qName, qTypeName, qTypeCode) = parseQuestion(dnsPayload)

    return ParsedDnsPacket(
      srcIp = srcIp,
      dstIp = dstIp,
      srcPort = srcPort,
      dstPort = dstPort,
      ipId = ipId,
      dnsPayload = dnsPayload,
      transactionId = transactionId,
      queryDomain = qName,
      queryTypeName = qTypeName,
      queryTypeCode = qTypeCode,
    )
  }

  fun buildIpUdpDnsResponse(request: ParsedDnsPacket, dnsResponsePayload: ByteArray): ByteArray {
    return buildIpUdpPacket(
      srcIp = request.dstIp,
      dstIp = request.srcIp,
      srcPort = request.dstPort,
      dstPort = request.srcPort,
      ipId = request.ipId xor 0x5A5A,
      payload = dnsResponsePayload,
    )
  }

  fun buildIpUdpPacket(
    srcIp: ByteArray,
    dstIp: ByteArray,
    srcPort: Int,
    dstPort: Int,
    ipId: Int,
    payload: ByteArray,
  ): ByteArray {
    val ipHeaderLen = 20
    val udpHeaderLen = 8
    val totalLen = ipHeaderLen + udpHeaderLen + payload.size
    val out = ByteArray(totalLen)

    out[0] = 0x45.toByte()
    out[1] = 0x00.toByte()
    writeUInt16(out, 2, totalLen)
    writeUInt16(out, 4, ipId)
    out[6] = 0x40.toByte()
    out[7] = 0x00.toByte()
    out[8] = 64.toByte()
    out[9] = 17.toByte()
    System.arraycopy(srcIp, 0, out, 12, 4)
    System.arraycopy(dstIp, 0, out, 16, 4)

    val ipChecksum = computeChecksum(out, 0, ipHeaderLen)
    writeUInt16(out, 10, ipChecksum)

    val udpStart = ipHeaderLen
    val udpLen = udpHeaderLen + payload.size
    writeUInt16(out, udpStart, srcPort)
    writeUInt16(out, udpStart + 2, dstPort)
    writeUInt16(out, udpStart + 4, udpLen)
    System.arraycopy(payload, 0, out, udpStart + udpHeaderLen, payload.size)

    val udpChecksum = computeTransportChecksum(
      srcIp = srcIp,
      dstIp = dstIp,
      protocol = 17,
      segment = out,
      offset = udpStart,
      length = udpLen,
      zeroIfZero = false,
    )
    writeUInt16(out, udpStart + 6, udpChecksum)

    return out
  }

  fun buildIpTcpPacket(
    srcIp: ByteArray,
    dstIp: ByteArray,
    srcPort: Int,
    dstPort: Int,
    seqNum: Long,
    ackNum: Long,
    flags: Int,
    windowSize: Int = 65535,
    mss: Int? = null,
    payload: ByteArray = ByteArray(0),
  ): ByteArray {
    val ipHeaderLen = 20
    val tcpHeaderLen = if (mss != null) 24 else 20
    val totalLen = ipHeaderLen + tcpHeaderLen + payload.size
    val out = ByteArray(totalLen)

    // IPv4 Header
    out[0] = 0x45.toByte()
    out[1] = 0x00.toByte()
    writeUInt16(out, 2, totalLen)
    writeUInt16(out, 4, (seqNum and 0xFFFFL).toInt())
    out[6] = 0x40.toByte()
    out[7] = 0x00.toByte()
    out[8] = 64.toByte()
    out[9] = 6.toByte() // TCP
    System.arraycopy(srcIp, 0, out, 12, 4)
    System.arraycopy(dstIp, 0, out, 16, 4)

    val ipChecksum = computeChecksum(out, 0, ipHeaderLen)
    writeUInt16(out, 10, ipChecksum)

    // TCP Header
    val tcpStart = ipHeaderLen
    writeUInt16(out, tcpStart, srcPort)
    writeUInt16(out, tcpStart + 2, dstPort)
    writeUInt32(out, tcpStart + 4, seqNum)
    writeUInt32(out, tcpStart + 8, ackNum)
    out[tcpStart + 12] = (((tcpHeaderLen / 4) shl 4) and 0xF0).toByte()
    out[tcpStart + 13] = (flags and 0xFF).toByte()
    writeUInt16(out, tcpStart + 14, windowSize.coerceIn(0, 65535))

    if (mss != null) {
      out[tcpStart + 20] = 0x02.toByte() // Kind: MSS
      out[tcpStart + 21] = 0x04.toByte() // Length: 4
      writeUInt16(out, tcpStart + 22, mss)
    }

    if (payload.isNotEmpty()) {
      System.arraycopy(payload, 0, out, tcpStart + tcpHeaderLen, payload.size)
    }

    val tcpChecksum = computeTransportChecksum(
      srcIp = srcIp,
      dstIp = dstIp,
      protocol = 6,
      segment = out,
      offset = tcpStart,
      length = tcpHeaderLen + payload.size,
      zeroIfZero = true,
    )
    writeUInt16(out, tcpStart + 16, tcpChecksum)

    return out
  }

  fun buildServFailResponse(queryPayload: ByteArray): ByteArray {
    if (queryPayload.size < 12) return queryPayload
    val resp = queryPayload.copyOf()
    val flags0 = resp[2].toInt() and 0xFF
    resp[2] = (flags0 or 0x80).toByte()
    resp[3] = 0x82.toByte() // RA=1, RCODE=2 (SERVFAIL)
    resp[6] = 0; resp[7] = 0
    resp[8] = 0; resp[9] = 0
    resp[10] = 0; resp[11] = 0
    return resp
  }

  fun buildEmptyNoErrorResponse(queryPayload: ByteArray): ByteArray {
    if (queryPayload.size < 12) return queryPayload
    val resp = queryPayload.copyOf()
    val flags0 = resp[2].toInt() and 0xFF
    resp[2] = (flags0 or 0x80).toByte()
    resp[3] = 0x80.toByte() // RA=1, RCODE=0 (NOERROR)
    resp[6] = 0; resp[7] = 0
    resp[8] = 0; resp[9] = 0
    resp[10] = 0; resp[11] = 0
    return resp
  }

  fun buildDnsQuery(domain: String, queryType: Int = 1, transactionId: Int = 0x1A2B): ByteArray {
    val labels = domain.trimEnd('.').split('.').filter { it.isNotEmpty() }
    val qNameSize = labels.sumOf { 1 + it.toByteArray(Charsets.UTF_8).size } + 1
    val out = ByteArray(12 + qNameSize + 4)
    writeUInt16(out, 0, transactionId)
    out[2] = 0x01.toByte()
    out[3] = 0x00.toByte()
    writeUInt16(out, 4, 1)

    var pos = 12
    for (label in labels) {
      val bytes = label.toByteArray(Charsets.UTF_8)
      val len = minOf(bytes.size, 63)
      out[pos++] = len.toByte()
      System.arraycopy(bytes, 0, out, pos, len)
      pos += len
    }
    out[pos++] = 0x00
    writeUInt16(out, pos, queryType)
    writeUInt16(out, pos + 2, 1)
    return out
  }

  fun extractResolvedAddresses(dnsResponse: ByteArray): List<String> {
    if (dnsResponse.size < 12) return emptyList()
    val qdCount = readUInt16(dnsResponse, 4)
    val anCount = readUInt16(dnsResponse, 6)
    if (anCount == 0) return emptyList()

    var offset = 12
    repeat(qdCount) {
      offset = skipName(dnsResponse, offset)
      if (offset < 0 || offset + 4 > dnsResponse.size) return emptyList()
      offset += 4
    }

    val results = mutableListOf<String>()
    repeat(anCount) {
      offset = skipName(dnsResponse, offset)
      if (offset < 0 || offset + 10 > dnsResponse.size) return results
      val type = readUInt16(dnsResponse, offset)
      val rdLength = readUInt16(dnsResponse, offset + 8)
      val rDataStart = offset + 10
      if (rDataStart + rdLength > dnsResponse.size) return results
      if (type == 1 && rdLength == 4) {
        val addr = Inet4Address.getByAddress(dnsResponse.copyOfRange(rDataStart, rDataStart + 4))
        addr.hostAddress?.let { results.add(it) }
      } else if (type == 28 && rdLength == 16) {
        val addr = Inet6Address.getByAddress(dnsResponse.copyOfRange(rDataStart, rDataStart + 16))
        addr.hostAddress?.let { results.add(it) }
      }
      offset = rDataStart + rdLength
    }
    return results
  }

  private fun parseQuestion(dns: ByteArray): Triple<String, String, Int> {
    if (dns.size < 13) return Triple("", "A", 1)
    val qdCount = readUInt16(dns, 4)
    if (qdCount == 0) return Triple("", "A", 1)

    val sb = StringBuilder()
    var pos = 12
    var jumps = 0
    while (pos < dns.size && jumps < 64) {
      val len = dns[pos].toInt() and 0xFF
      if (len == 0) {
        pos++
        break
      }
      if ((len and 0xC0) == 0xC0) {
        pos += 2
        break
      }
      pos++
      if (pos + len > dns.size) break
      if (sb.isNotEmpty()) sb.append('.')
      sb.append(String(dns, pos, len, Charsets.UTF_8))
      pos += len
      jumps++
    }

    val qType = if (pos + 2 <= dns.size) readUInt16(dns, pos) else 1
    val qTypeName = when (qType) {
      1 -> "A"
      28 -> "AAAA"
      65 -> "HTTPS"
      16 -> "TXT"
      5 -> "CNAME"
      else -> "T$qType"
    }
    return Triple(sb.toString(), qTypeName, qType)
  }

  private fun skipName(dns: ByteArray, startOffset: Int): Int {
    var pos = startOffset
    var steps = 0
    while (pos < dns.size && steps < 128) {
      val len = dns[pos].toInt() and 0xFF
      if (len == 0) return pos + 1
      if ((len and 0xC0) == 0xC0) return pos + 2
      pos += 1 + len
      steps++
    }
    return -1
  }

  fun readUInt16(data: ByteArray, offset: Int): Int =
    ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

  fun readUInt32(data: ByteArray, offset: Int): Long =
    ((data[offset].toLong() and 0xFFL) shl 24) or
      ((data[offset + 1].toLong() and 0xFFL) shl 16) or
      ((data[offset + 2].toLong() and 0xFFL) shl 8) or
      (data[offset + 3].toLong() and 0xFFL)

  fun writeUInt16(data: ByteArray, offset: Int, value: Int) {
    data[offset] = ((value ushr 8) and 0xFF).toByte()
    data[offset + 1] = (value and 0xFF).toByte()
  }

  fun writeUInt32(data: ByteArray, offset: Int, value: Long) {
    data[offset] = ((value ushr 24) and 0xFFL).toByte()
    data[offset + 1] = ((value ushr 16) and 0xFFL).toByte()
    data[offset + 2] = ((value ushr 8) and 0xFFL).toByte()
    data[offset + 3] = (value and 0xFFL).toByte()
  }

  fun computeChecksum(data: ByteArray, offset: Int, length: Int): Int {
    var sum = 0L
    var i = offset
    val end = offset + length
    while (i + 1 < end) {
      sum += (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).toLong()
      i += 2
    }
    if (i < end) {
      sum += ((data[i].toInt() and 0xFF) shl 8).toLong()
    }
    while ((sum ushr 16) != 0L) {
      sum = (sum and 0xFFFF) + (sum ushr 16)
    }
    return (sum.inv() and 0xFFFF).toInt()
  }

  fun computeTransportChecksum(
    srcIp: ByteArray,
    dstIp: ByteArray,
    protocol: Int,
    segment: ByteArray,
    offset: Int,
    length: Int,
    zeroIfZero: Boolean,
  ): Int {
    var sum = 0L
    sum += (((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)).toLong()
    sum += (((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)).toLong()
    sum += (((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)).toLong()
    sum += (((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)).toLong()
    sum += protocol.toLong()
    sum += length.toLong()

    var i = offset
    val end = offset + length
    while (i + 1 < end) {
      sum += (((segment[i].toInt() and 0xFF) shl 8) or (segment[i + 1].toInt() and 0xFF)).toLong()
      i += 2
    }
    if (i < end) {
      sum += ((segment[i].toInt() and 0xFF) shl 8).toLong()
    }
    while ((sum ushr 16) != 0L) {
      sum = (sum and 0xFFFF) + (sum ushr 16)
    }
    val finalChecksum = (sum.inv() and 0xFFFF).toInt()
    return if (!zeroIfZero && finalChecksum == 0) 0xFFFF else finalChecksum
  }
}
