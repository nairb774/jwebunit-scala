package org.no.ip.bca.jwebunit.scala

import com.gargoylesoftware.htmlunit.Page
import java.lang.ref.{ ReferenceQueue, PhantomReference }
import java.net.URL
import net.sourceforge.jwebunit.api.IElement
import net.sourceforge.jwebunit.htmlunit.{ HtmlUnitTestingEngineImpl, HtmlUnitElementImpl }
import net.sourceforge.jwebunit.junit.WebTester
import ntlm.NTLMTestingEngine
import scalaj.collection.Imports._

private object SWebUnit extends Runnable {
  private var outstanding: Map[PhantomReference[SWebUnit], WebTester] = Map.empty
  private val queue = new ReferenceQueue[SWebUnit]
  private def add(swt: SWebUnit): Unit = {
    val count = this.synchronized {
      outstanding += new PhantomReference(swt, queue) -> swt.wt
      outstanding.size
    }
    if (count == 1) {
      val thread = new Thread(this)
      thread setDaemon true
      thread setName "SWebUnit browser auto closer thread: 1"
      thread.start
    }
  }

  def run: Unit = {
    val ref = queue.remove.asInstanceOf[PhantomReference[SWebUnit]]
    val (wt, size) = this.synchronized {
      val out = outstanding(ref)
      outstanding -= ref
      (out, outstanding.size)
    }
    wt.closeBrowser
    Thread.currentThread.setName("SWebUnit browser auto closer thread: " + size)
    if (size > 0)
      run
  }
}

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
      wt setTestingEngineKey NTLMTestingEngine.register
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
  
  object close {
    def browser = wt.closeBrowser
    def window = wt.closeWindow
  }

  object element {
    def byId(id: Symbol): IElement = byId(_stringForSymbol(id))
    def byId(id: String): IElement = wt getElementById id
    def byXPath(xpath: String): IElement = wt getElementByXPath xpath
  }
  object elements {
    def byXPath(xpath: String): Seq[IElement] = wt getElementsByXPath xpath asScala
  }
  object exists {
    def form(name: String) = wt.getTestingEngine.hasForm(name)
    def formParameter(name: String) = wt.getTestingEngine.hasFormParameterNamed(name)
    def id(id: String) = wt.getTestingEngine.hasElement(id)
    def XPath(xpath: String) = wt.getTestingEngine.hasElementByXPath(xpath)
  }
  def form(formName: Symbol)(f: => Unit): Unit = form(_stringForSymbol(formName))(f)
  def form(formName: String)(f: => Unit): Unit = {
    wt setWorkingForm formName
    f
  }
  def frame[T](s: Symbol)(f: => T): T = frame(_stringForSymbol(s))(f)
  def frame[T](frame: String)(f: => T): T = {
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
    def fromId(id: String): String = byXPath("id('" + id + "')")
    def byXPath(xpath: String): String = wt getElementTextByXPath xpath
  }
  object until {
    def form(name: String) = await("Form: " + name) { exists form name }
    def formParameter(name: String) = await("Form name: " + name) { exists formParameter name }
    def id(id: String) = await("ID: " + id) { exists id id }
    def XPath(xpath: String) = await("XPath: " + xpath) { exists XPath xpath }
  }

  private def await(fr: String)(f: => Boolean) = {
    val end = System.nanoTime + 600E9.toLong;
    while (!f) {
      if (System.nanoTime > end) {
        throw new IllegalStateException(fr)
      }
      Thread.sleep(10)
    }
  }

  def pageSource = wt.getPageSource
  def serverResponse = wt.getServerResponse

  class FormAssign private[SWebUnit] (key: String) {
    def <~(value: String): Unit = wt setTextField (key, value)
    def pick(value: String): Unit = wt.selectOptionByValue(key, value)
  }
  implicit def toFormAssign(key: String): FormAssign = new FormAssign(key)
  implicit def toFormAssign(s: Symbol): FormAssign = new FormAssign(_stringForSymbol(s))

  // Must be last
  SWebUnit add this
}

