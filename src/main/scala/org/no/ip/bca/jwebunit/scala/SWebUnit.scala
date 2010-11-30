package org.no.ip.bca.jwebunit.scala

import java.net.URL
import net.sourceforge.jwebunit.junit.WebTester
import net.sourceforge.jwebunit.api.IElement
import net.sourceforge.jwebunit.htmlunit.{ HtmlUnitTestingEngineImpl, HtmlUnitElementImpl }
import com.gargoylesoftware.htmlunit.Page
import scalaj.collection.Imports._

trait SWebUnit {
  private val wt = new WebTester
  private var afterLinkClick: Option[() => Unit] = None

  def stringForSymbol(s: Symbol): Option[String] = None
  private def _stringForSymbol(s: Symbol) = stringForSymbol(s) match {
    case Some(str) => str
    case None => throw new IllegalArgumentException("Symbol: " + s + " could not be converted to a string")
  }
  def baseUrl: URL = wt.getTestContext.getBaseUrl
  def baseUrl_=(url: String): Unit = wt setBaseUrl url
  def baseUrl_=(url: URL): Unit = wt setBaseUrl url
  def pageUrl: URL = wt.getTestingEngine.getPageURL
  def pageUrl_=(url: String): Unit = wt beginAt url

  object authorize {
    def ntlm(user: String, password: String, domain: String): Unit = {
      wt setTestingEngineKey NtlmTestingEngine.register
      wt.getTestContext.setNTLMAuthorization(user, password, domain)
    }
  }

  object click {
    def link(text: Symbol): Unit = link(_stringForSymbol(text))
    def link(text: String): Unit = {
      wt clickLinkWithText text
      afterLinkClick foreach { _() }
    }
    def button(text: Symbol): Unit = button(_stringForSymbol(text))
    def button(text: String): Unit = wt clickButtonWithText text
    def XPath(xpath: String): Unit = wt clickElementByXPath xpath
    def id(s: Symbol): Unit = id(_stringForSymbol(s))
    def id(id: String): Unit = on(element byId id)
    def on(element: IElement): Unit = element match {
      case e: HtmlUnitElementImpl => e.getHtmlElement.click[Page]
      case e: IElement => throw new IllegalArgumentException("Unable to click IElement of type: " + e.getClass)
    }
  }

  object element {
    def byId(id: Symbol): IElement = byId(_stringForSymbol(id))
    def byId(id: String): IElement = wt getElementById id
    def byXPath(xpath: String): IElement = wt getElementByXPath xpath
  }
  object elements {
    def byXPath(xpath: String): Seq[IElement] = wt getElementsByXPath xpath asScala
  }
  def form(formName: Symbol)(f: => Unit): Unit = form(_stringForSymbol(formName))(f)
  def form(formName: String)(f: => Unit): Unit = {
    wt setWorkingForm formName
    f
  }
  def frame(s: Symbol)(f: => Unit): Unit = frame(_stringForSymbol(s))(f)
  def frame(frame: String)(f: => Unit): Unit = {
    val windowName = wt.getTestingEngine match {
      case html: HtmlUnitTestingEngineImpl => html.getCurrentWindow.getName
      case other => throw new IllegalStateException("Support for " + other.getClass + " not implemented")
    }
    if (afterLinkClick.isDefined) throw new IllegalStateException("afterLinkClick already in use")
    afterLinkClick = Some { () =>
      wt gotoWindow windowName
      wt gotoFrame frame
    }
    wt gotoFrame frame
    try {
      f
    } finally {
      afterLinkClick = None
      wt gotoWindow windowName
    }
  }
  object go {
    def to(url: String): Unit = wt gotoPage url
    def to(url: URL): Unit = to(url.toExternalForm)
  }
  object text {
    def byXPath(xpath: String): String = wt getElementTextByXPath xpath
  }

  def pageSource = wt.getPageSource
  def serverResponse = wt.getServerResponse

  class FormAssign private[SWebUnit] (key: String) {
    def <~(value: String): Unit = wt setTextField (key, value)
  }
  implicit def toFormAssign(key: String): FormAssign = new FormAssign(key)
  implicit def toFormAssign(s: Symbol): FormAssign = new FormAssign(_stringForSymbol(s))
}