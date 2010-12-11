package org.no.ip.bca.jwebunit.scala.ntlm

import java.nio.charset.Charset
import java.nio.charset.UnsupportedCharsetException
import java.util.Arrays.equals

object Flag {
  final case object NEGOTIATE_UNICODE extends Flag(0x00000001)
  final case object NEGOTIATE_OEM extends Flag(0x00000002)
  final case object REQUEST_TARGET extends Flag(0x00000004)
  final case object NEGOTIATE_SIGN extends Flag(0x00000010)
  final case object NEGOTIATE_SEAL extends Flag(0x00000020)
  final case object NEGOTIATE_DATAGRAM_STYLE extends Flag(0x00000040)
  final case object NEGOTIATE_LAN_MANAGER_KEY extends Flag(0x00000080)
  final case object NEGOTIATE_NETWARE extends Flag(0x00000100)
  final case object NEGOTIATE_NTLM extends Flag(0x00000200)
  final case object NEGOTIATE_ANONYMOUS extends Flag(0x00000800)
  final case object NEGOTIATE_DOMAIN_SUPPLIED extends Flag(0x00001000)
  final case object NEGOTIATE_WORKSTATION_SUPPLIED extends Flag(0x00002000)
  final case object NEGOTIATE_LOCAL_CALL extends Flag(0x00004000)
  final case object NEGOTIATE_ALWAYS_SIGN extends Flag(0x00008000)
  final case object TARGET_TYPE_DOMAIN extends Flag(0x00010000)
  final case object TARGET_TYPE_SERVER extends Flag(0x00020000)
  final case object TARGET_TYPE_SHARE extends Flag(0x00040000)
  final case object NEGOTIATE_NTLM2_KEY extends Flag(0x00080000)
  final case object REQUEST_INIT_RESPONSE extends Flag(0x00100000)
  final case object REQUEST_ACCEPT_RESPONSE extends Flag(0x00200000)
  final case object REQUEST_NON_NT_SESSION_KEY extends Flag(0x00400000)
  final case object NEGOTIATE_TARGET_INFO extends Flag(0x00800000)
  final case object NEGOTIATE_128 extends Flag(0x20000000)
  final case object NEGOTIATE_KEY_EXCHANGE extends Flag(0x40000000)
  final case object NEGOTIATE_56 extends Flag(0x80000000)

  private val allFlags = Set(
    NEGOTIATE_UNICODE, NEGOTIATE_OEM, REQUEST_TARGET, NEGOTIATE_SIGN, NEGOTIATE_SEAL, NEGOTIATE_DATAGRAM_STYLE,
    NEGOTIATE_LAN_MANAGER_KEY, NEGOTIATE_NETWARE, NEGOTIATE_NTLM, NEGOTIATE_ANONYMOUS, NEGOTIATE_DOMAIN_SUPPLIED,
    NEGOTIATE_WORKSTATION_SUPPLIED, NEGOTIATE_LOCAL_CALL, NEGOTIATE_ALWAYS_SIGN, TARGET_TYPE_DOMAIN, TARGET_TYPE_SERVER,
    TARGET_TYPE_SHARE, NEGOTIATE_NTLM2_KEY, REQUEST_INIT_RESPONSE, REQUEST_ACCEPT_RESPONSE, REQUEST_NON_NT_SESSION_KEY,
    NEGOTIATE_TARGET_INFO, NEGOTIATE_128, NEGOTIATE_KEY_EXCHANGE, NEGOTIATE_56)

  def parseFlags(flags: Int): Set[Flag] = allFlags filter (flag => (flag.mask & flags) != 0)
}

sealed abstract class Flag(val mask: Int) extends Product

object NTLM {
  val UNICODE_CHARSET = Charset forName "UTF-16LE"
  var DEFAULT_CHARSET: Charset = try {
    Charset forName "Cp850" // Test this charset
  } catch {
    case e: UnsupportedCharsetException =>
      // If Cp850 does not exist fall back to ASCII
      Charset forName "US-ASCII"
  }

  private[ntlm] val ntlmHeader = Array[Byte]('N', 'T', 'L', 'M', 'S', 'S', 'P', 0)
  private[ntlm] def getCharset(flags: Set[Flag]): Charset =
    if (flags contains Flag.NEGOTIATE_UNICODE) UNICODE_CHARSET
    else if (flags contains Flag.NEGOTIATE_OEM) DEFAULT_CHARSET
    else throw new IllegalArgumentException("Unable to determine charset from flags: " + flags)

  private class Parser(array: Array[Byte]) {
    private var pos = 0
    private var maxFixedSize = array.length
    def hasMore = pos < maxFixedSize

    def isNTLMHeader = 0 until ntlmHeader.length forall { i =>
      val ret = ntlmHeader(i) == array(pos)
      pos += 1
      ret
    }

    def readBytes(size: Int) = {
      val block = new Array[Byte](size)
      System.arraycopy(array, pos, block, 0, size)
      pos += size
      block
    }

    def readInt: Int = {
      val value = array(pos) | (array(pos + 1) << 8) | (array(pos + 2) << 16) | (array(pos + 3) << 24)
      pos += 4
      value
    }

    def readFlags = {
      val flags = readInt
      println("flags: " + flags)
      val f = Flag.parseFlags(flags)
      println(f)
      f
    }

    def readShort: Int = {
      val value = array(pos) | (array(pos + 1) << 8)
      pos += 2
      value
    }

    def readSecurityBuffer = {
      val length = readShort
      readShort // allocated space - ignored
      val offset = readInt
      maxFixedSize = maxFixedSize min offset
      val bytes = new Array[Byte](length)
      System.arraycopy(array, offset, bytes, 0, length)
      bytes
    }

    def readSecurityString(charset: Charset) = new String(readSecurityBuffer, charset.name)
    def readOemSecurityString = readSecurityString(DEFAULT_CHARSET)
  }

  private def ifFlag[T](flags: Set[Flag], flag: Flag)(func: => T) = if (flags contains flag) Some(func) else None

  private def parse(array: Array[Byte]) = {
    val parser = new Parser(array)
    if (!parser.isNTLMHeader) {
      throw new IllegalStateException("NTLM header not found")
    }
    parser.readInt match {
      case 1 => parseType1(parser)
      case 2 => parseType2(parser)
      case 3 => parseType3(null, parser) // TODO -> take message 2 in for parsing the 3rd message
    }
  }

  def parse2(array: Array[Byte]): Message2 = {
    val parser = new Parser(array)
    if (!parser.isNTLMHeader) {
      throw new IllegalArgumentException("NTLM header not found")
    }
    if (parser.readInt != 2) throw new IllegalArgumentException("Expected a message of type 2")
    parseType2(parser)
  }

  private def parseType1(parser: Parser) = {
    val flags = parser.readFlags
    val domain = ifFlag(flags, Flag.NEGOTIATE_DOMAIN_SUPPLIED)(parser.readOemSecurityString)
    val workstation = ifFlag(flags, Flag.NEGOTIATE_WORKSTATION_SUPPLIED)(parser.readOemSecurityString)
    new Message1(flags, domain, workstation)
  }

  private def parseType2(parser: Parser) = {
    val targetNameBytes = parser.readSecurityBuffer
    val flags = parser.readFlags
    val targetName = new String(targetNameBytes, getCharset(flags).name)
    val challenge = parser.readBytes(8)
    println("challenge: " + java.util.Arrays.toString(challenge))
    val context = if (parser.hasMore) Some(parser.readBytes(8)) else None
    val targetInformation = if (parser.hasMore) Some(parser.readSecurityBuffer) else None
    new Message2(flags, targetName, challenge, targetInformation)
  }

  private def parseType3(message2: Message2, parser: Parser) = {
    val charset = getCharset(message2.flags)
    val lmResponse = parser.readSecurityBuffer
    val ntlmResponse = parser.readSecurityBuffer
    val targetName = parser.readSecurityString(charset)
    val userName = parser.readSecurityString(charset)
    val workstationName = parser.readSecurityString(charset)
    val sessionKey = if (parser.hasMore) Some(parser.readSecurityBuffer) else None
    val flags = if (parser.hasMore) Some(parser.readFlags) else None
  }
}

class MessageBuilder {
  private abstract class Action {
    val fixedSize: Int
    val dynamicSize: Int
    def set(array: Array[Byte], fixed: Int, dynamic: Int): Unit
  }
  private abstract class FixedAction( final val fixedSize: Int) extends Action {
    final val dynamicSize: Int = 0
  }
  private abstract class DynamicAction( final val dynamicSize: Int) extends Action {
    final val fixedSize: Int = 0
  }
  private var actions = new scala.collection.mutable.ArrayBuffer[Action]
  private def writeInt(array: Array[Byte], pos: Int, value: Int) = {
    array(pos) = value.toByte
    array(pos + 1) = (value >>> 8).toByte
    array(pos + 2) = (value >>> 16).toByte
    array(pos + 3) = (value >>> 24).toByte
  }
  private def withAction(a: Action) = {
    actions += a
    this
  }
  def addNTLMHeader = addBytes(NTLM.ntlmHeader)
  def addBytes(bytes: Array[Byte]) = this withAction new FixedAction(bytes.length) {
    def set(array: Array[Byte], fixed: Int, dynamic: Int) =
      System.arraycopy(bytes, 0, array, fixed, bytes.length)
  }
  def addShort(value: Int) = this withAction new FixedAction(2) {
    def set(array: Array[Byte], fixed: Int, dynamic: Int) = {
      array(fixed) = value.toByte
      array(fixed + 1) = (value >>> 8).toByte
    }
  }
  def addInt(value: Int) = this withAction new FixedAction(4) {
    def set(array: Array[Byte], fixed: Int, dynamic: Int) = writeInt(array, fixed, value)
  }
  def addFlags(flags: Set[Flag]) = addInt((0 /: flags)((flags, flag) => flags | flag.mask))
  def addSecurityBuffer(buffer: Array[Byte]) = {
    addShort(buffer.length)
    addShort(buffer.length)
    this withAction new FixedAction(4) {
      def set(array: Array[Byte], fixed: Int, dynamic: Int) = writeInt(array, fixed, dynamic)
    }
    this withAction new DynamicAction(buffer.length) {
      def set(array: Array[Byte], fixed: Int, dynamic: Int) =
        System.arraycopy(buffer, 0, array, dynamic, buffer.length)
    }
  }

  def addSecurityString(string: String, charset: Charset) =
    addSecurityBuffer(string getBytes charset.name)

  def toArray = {
    val (fixedSize, dynamicSize) = ((0, 0) /: actions)((size, action) => (size._1 + action.fixedSize, size._2 + action.dynamicSize))
    val buffer = new Array[Byte](fixedSize + dynamicSize)
    ((0, fixedSize) /: actions) { (pos, action) =>
      action.set(buffer, pos._1, pos._2)
      (pos._1 + action.fixedSize, pos._2 + action.dynamicSize)
    }
    buffer
  }
}

final class Message1 private[ntlm] (flags: Set[Flag], domain: Option[String], workstation: Option[String]) {
  def this() = this(Set(Flag.NEGOTIATE_NTLM, Flag.NEGOTIATE_OEM), None, None)
  def this(domain: String, workstation: String) =
    this(
      Set(Flag.NEGOTIATE_NTLM, Flag.NEGOTIATE_OEM, Flag.NEGOTIATE_DOMAIN_SUPPLIED, Flag.NEGOTIATE_WORKSTATION_SUPPLIED),
      Some(domain),
      Some(workstation))

  def toBytes = {
    val builder = new MessageBuilder
    builder.addNTLMHeader
    builder.addInt(1)
    builder.addFlags(flags)
    domain foreach { builder addSecurityString (_, NTLM.DEFAULT_CHARSET) }
    workstation foreach { builder addSecurityString (_, NTLM.DEFAULT_CHARSET) }
    builder.toArray
  }

  def withDomain(domain: String) =
    new Message1(flags + Flag.NEGOTIATE_DOMAIN_SUPPLIED, Some(domain.toUpperCase), workstation)

  def withWorkstation(workstation: String) =
    new Message1(flags + Flag.NEGOTIATE_WORKSTATION_SUPPLIED, domain, Some(workstation.toUpperCase))
  def withUnicode = new Message1(flags + Flag.NEGOTIATE_UNICODE, domain, workstation)
}

final class Message2 private[ntlm] (val flags: Set[Flag], val targetName: String, _challenge: Array[Byte], _targetInformation: Option[Array[Byte]]) {
  def challenge = _challenge.clone
  def targetInformation = _targetInformation map { _.clone }
  def toBytes = {
    val builder = new MessageBuilder
    builder.addNTLMHeader
    builder.addInt(2)
    builder.addSecurityString(targetName, NTLM.getCharset(flags))
    builder.addFlags(flags)
    builder.addBytes(challenge)
    builder.toArray
  }
}

object Message3 {
  import java.nio._
  import java.security._
  import javax.crypto._
  import javax.crypto.spec._
  /** Since MD4 is not standard - check for one that is registered, then try for a hidden sun one. Or else fail. */
  private val md4Factory: () => MessageDigest = (try {
    MessageDigest.getInstance("MD4")
    Some(() => MessageDigest.getInstance("MD4"))
  } catch {
    case e: NoSuchAlgorithmException => None
  }) orElse {
    try {
      val clazz = Class.forName("sun.security.provider.MD4")
      val method = clazz.getMethod("getInstance")
      Some(() => method.invoke(null).asInstanceOf[MessageDigest])
    } catch {
      case e: ClassNotFoundException => None
      case e: NoSuchMethodException => None
      case e: SecurityException => None
    }
  } getOrElse (throw new IllegalStateException("MD4 provider not found"))

  //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider)

  private def des(keyBytes: Array[Byte], value: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("DES")
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DES"))
    cipher.doFinal(value)
  }

  private def doMD4(bytes: ByteBuffer) = {
    val digester = MessageDigest.getInstance("MD4", "BC")
    digester.update(bytes)
    digester.digest
  }

  private def passwordHash(password: Array[Char]) = doMD4(NTLM.UNICODE_CHARSET.encode(CharBuffer.wrap(password)))

  private def doV1Hash(key: Array[Byte], challenge: Array[Byte]) = {
    val paddedKey = key ++ Array[Byte](0, 0, 0, 0, 0)
    des(paddedKey take 7, challenge) ++ des(paddedKey drop 7 take 7, challenge) ++ des(paddedKey drop 14, challenge)
  }

  private def lmResponse(password: Array[Char], challenge: Array[Byte]) = {
    val passwordBytes = new Array[Byte](14)
    val byteBuffer = NTLM.DEFAULT_CHARSET.encode(java.nio.CharBuffer.wrap(password map { _.toUpper }))
    byteBuffer.get(passwordBytes, 0, byteBuffer.remaining min 14)
    val value = Array[Byte]('K', 'G', 'S', '!', '@', '#', '$', '%')
    doV1Hash(des(passwordBytes take 7, value) ++ des(passwordBytes drop 7, value), challenge)
  }

  private def ntlmResponse(password: Array[Char], challenge: Array[Byte]) = doV1Hash(passwordHash(password), challenge)

  private def hmacMD5(key: Array[Byte], data: Array[Byte]) = {
    val mac = javax.crypto.Mac.getInstance("HmacMD5")
    mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacMD5"))
    mac.doFinal(data)
  }

  private def v2Hash(username: String, password: Array[Char], domain: String, challenge: Array[Byte], blob: Array[Byte] => Array[Byte]) = {
    val pwHash = passwordHash(password)
    val ntlmV2Hash = hmacMD5(pwHash, (username.toUpperCase + domain).getBytes(NTLM.UNICODE_CHARSET.name))
    val random = new java.security.SecureRandom()
    val clientNonce = new Array[Byte](8)
    random.nextBytes(clientNonce)
    val b = blob(clientNonce)
    hmacMD5(ntlmV2Hash, challenge ++ b) ++ b
  }

  private def lmV2Response(username: String, password: Array[Char], targetName: String, challenge: Array[Byte]) = {
    v2Hash(username, password, targetName, challenge, nonce => nonce)
  }

  private def ntlmV2Response(username: String, password: Array[Char], domain: String, targetInformation: Array[Byte], challenge: Array[Byte]) = {
    val empty4Bytes = new Array[Byte](4)
    val time = (System.currentTimeMillis + 11644473600000L) * 10000L
    val timestamp = Array[Byte](
      (time & 0xFFL).toByte,
      ((time >>> 8) & 0xFFL).toByte,
      ((time >>> 16) & 0xFFL).toByte,
      ((time >>> 24) & 0xFFL).toByte,
      ((time >>> 32) & 0xFFL).toByte,
      ((time >>> 40) & 0xFFL).toByte,
      ((time >>> 48) & 0xFFL).toByte,
      ((time >>> 56) & 0xFFL).toByte)

    v2Hash(username, password, domain, challenge, { nonce =>
      Array[Byte](1, 1, 0, 0) ++
        empty4Bytes ++
        timestamp ++
        nonce ++
        empty4Bytes ++
        targetInformation ++
        empty4Bytes
    })
  }

  def signLevel0(m2: Message2, username: String, password: Array[Char], domain: String, workstation: String): Message3 = {
    if (m2.flags contains Flag.NEGOTIATE_NTLM2_KEY) {
      // TODO
      throw new IllegalStateException("NEGOTIATE_NTLM2_KEY not yet supported")
    } else {
      val lm = lmResponse(password, m2.challenge)
      val ntlm = ntlmResponse(password, m2.challenge)

      var flags = Set[Flag](Flag.NEGOTIATE_NTLM)
      if (m2.flags contains Flag.NEGOTIATE_UNICODE) flags += Flag.NEGOTIATE_UNICODE
      else flags += Flag.NEGOTIATE_OEM

      new Message3(lm, ntlm, domain, username, workstation, flags, None)
    }
  }

  def signLevel1(m2: Message2, username: String, password: Array[Char], domain: String, workstation: String): Message3 =
    signLevel0(m2, username, password, domain, workstation)

  def signLevel2(m2: Message2, username: String, password: Array[Char], domain: String, workstation: String): Message3 = {
    val ntlm = ntlmResponse(password, m2.challenge)

    var flags = Set[Flag](Flag.NEGOTIATE_NTLM)
    if (m2.flags contains Flag.NEGOTIATE_UNICODE) flags += Flag.NEGOTIATE_UNICODE
    else flags += Flag.NEGOTIATE_OEM

    new Message3(ntlm, ntlm, domain, username, workstation, flags, None)
  }

  def signLevel3(m2: Message2, username: String, password: Array[Char], domain: String, workstation: String): Message3 = {
    val lm = lmV2Response(username, password, domain, m2.challenge)
    val ntlm = ntlmV2Response(username, password, domain, m2.targetInformation.get, m2.challenge)

    if (m2.flags contains Flag.NEGOTIATE_SIGN) {
      throw new IllegalArgumentException("NEGOTIATE_SIGN not yet supported")
    }

    var flags = Set[Flag](Flag.NEGOTIATE_NTLM)
    if (m2.flags contains Flag.NEGOTIATE_UNICODE) flags += Flag.NEGOTIATE_UNICODE
    else flags += Flag.NEGOTIATE_OEM

    new Message3(lm, ntlm, domain, username, workstation, flags, None)
  }

  def signLevel4(m2: Message2, username: String, password: Array[Char], domain: String, workstation: String): Message3 =
    signLevel3(m2, username, password, domain, workstation)

  def signLevel5(m2: Message2, username: String, password: Array[Char], domain: String, workstation: String): Message3 =
    signLevel3(m2, username, password, domain, workstation)
}

class Message3(lm: Array[Byte], ntlm: Array[Byte], domain: String, username: String, workstation: String, flags: Set[Flag], sessionKey: Option[Array[Byte]]) {
  def toBytes = {
    val builder = new MessageBuilder
    builder.addNTLMHeader
    builder.addInt(3)
    builder.addSecurityBuffer(lm)
    builder.addSecurityBuffer(ntlm)
    println(java.util.Arrays.toString(lm))
    println(java.util.Arrays.toString(ntlm))

    val charset = NTLM.getCharset(flags)
    builder.addSecurityString(domain, charset)
    builder.addSecurityString(username, charset)
    builder.addSecurityString(workstation, charset)

    builder.addSecurityBuffer(sessionKey getOrElse Array())
    builder.addFlags(flags)
    builder.toArray
  }
}
