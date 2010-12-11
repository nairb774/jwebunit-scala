package org.no.ip.bca.jwebunit.scala

import org.apache.http.auth.AuthSchemeFactory
import org.apache.http.impl.auth.NTLMEngine
import org.apache.http.impl.auth.NTLMScheme
import org.apache.http.params.HttpParams

import org.apache.commons.codec.binary.Base64
import org.apache.commons.codec.binary.StringUtils

class NTLMSchemeFactory extends AuthSchemeFactory {
  override def newInstance(params: HttpParams) = new NTLMScheme(new LocalNTLMEngine())
}

class LocalNTLMEngine extends NTLMEngine {
  private def toBase64(bytes: Array[Byte]): String = StringUtils.newStringUtf8(Base64.encodeBase64(bytes, false))
    
  override def generateType1Msg(domain: String, workstation: String): String =
    toBase64(new ntlm.Message1().withWorkstation(workstation).withDomain(domain).withUnicode.toBytes)

  override def generateType3Msg(username: String, password: String, domain: String, workstation: String,
    challenge: String): String =
    toBase64(ntlm.Message3.signLevel5(ntlm.NTLM.parse2(Base64.decodeBase64(challenge)), username, password.toCharArray, domain, workstation).toBytes)
}
