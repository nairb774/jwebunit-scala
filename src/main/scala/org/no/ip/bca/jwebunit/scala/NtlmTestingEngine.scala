package org.no.ip.bca.jwebunit.scala

import net.sourceforge.jwebunit.htmlunit.HtmlUnitTestingEngineImpl
import net.sourceforge.jwebunit.util.TestingEngineRegistry

object NtlmTestingEngine {
  def register = {
    val key = classOf[NtlmTestingEngine].getName
    try {
      TestingEngineRegistry.addTestingEngine(key, classOf[NtlmTestingEngine].getName)
    } catch {
      case e: ClassNotFoundException => throw new RuntimeException(e)
    }
    key
  }
}

class NtlmTestingEngine extends HtmlUnitTestingEngineImpl {
  override protected def createWebClient() = {
    val webClient = super.createWebClient
    webClient setWebConnection new NtlmWebConnection(webClient)
    webClient
  }
}
