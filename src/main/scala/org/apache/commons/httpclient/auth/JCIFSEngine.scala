package org.apache.commons.httpclient.auth

import java.nio.charset.Charset
import java.nio.charset.UnsupportedCharsetException
import org.apache.http.impl.auth.NTLMEngine

object JCIFSEngine {
  var DEFAULT_CHARSET = try {
    Charset forName "Cp850" // Test this charset
    "Cp850"
  } catch {
    case e: UnsupportedCharsetException =>
      // If Cp850 does not exist fall back to ASCII
      "US-ASCII"
  }
}

class JCIFSEngine extends NTLMEngine {
  var CHARSET = JCIFSEngine.DEFAULT_CHARSET
  private lazy val ntlm = {
    val n = new NTLM()
    n setCredentialCharset CHARSET
    n
  }

  override def generateType1Msg(domain: String, workstation: String): String =
    ntlm.getType1Message(workstation, domain)

  override def generateType3Msg(username: String, password: String, domain: String, workstation: String,
    challenge: String): String =
    ntlm.getType3Message(username, password, workstation, domain, ntlm.parseType2Message(challenge))
}
