package org.no.ip.bca.jwebunit.scala.ntlm

import net.sourceforge.jwebunit.htmlunit.HtmlUnitTestingEngineImpl
import net.sourceforge.jwebunit.util.TestingEngineRegistry

object NTLMTestingEngine {
  def register = {
    val key = classOf[NTLMTestingEngine].getName
    try {
      TestingEngineRegistry.addTestingEngine(key, classOf[NTLMTestingEngine].getName)
    } catch {
      case e: ClassNotFoundException => throw new RuntimeException(e)
    }
    key
  }
}

class NTLMTestingEngine extends HtmlUnitTestingEngineImpl {
  override protected def createWebClient() = {
    val webClient = super.createWebClient
    webClient setWebConnection new NTLMWebConnection(webClient)
    webClient
  }
}
