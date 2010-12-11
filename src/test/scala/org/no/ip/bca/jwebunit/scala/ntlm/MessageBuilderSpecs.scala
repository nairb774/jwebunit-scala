package org.no.ip.bca.jwebunit.scala.ntlm

import java.util.Arrays

import org.specs._
import org.specs.matcher.Matcher

class MessageBuilderTest extends SpecificationWithJUnit {
  object matchArray {
    def apply(seq: Int*) = new matchArray(seq map { _.toByte } toArray)
  }
  case class matchArray(expect: Array[Byte]) extends Matcher[Array[Byte]]() {
    def apply(_actual: => Array[Byte]) = {
      val actual = _actual
      (java.util.Arrays.equals(actual, expect), "success", "Had: " + Arrays.toString(actual) + " wanted: " + Arrays.toString(expect))
    }
  }

  "addNTLMHeader" should {
    val builder = new MessageBuilder
    "8 bytes long" >> { builder.addNTLMHeader.toArray.length mustEqual 8 }
    "be the correct value" >> { builder.addNTLMHeader.toArray must matchArray('N', 'T', 'L', 'M', 'S', 'S', 'P', 0) }
  }

  "addShort" should {
    val builder = new MessageBuilder
    "be 2 bytes long" >> { builder.addShort(0).toArray.length mustEqual 2 }
    "go from lsb to msb" >> { builder.addShort(0xAABB).toArray must matchArray(0xBB, 0xAA) }
    "truncate int values" >> { builder.addShort(0xAABB0000).toArray must matchArray(0, 0) }
  }

  "addInt" should {
    val builder = new MessageBuilder
    "be 4 bytes long" >> { builder.addInt(0).toArray.length mustEqual 4 }
    "go from lsb to msb" >> { builder.addInt(0xAABBCCDD).toArray must matchArray(0xDD, 0xCC, 0xBB, 0xAA) }
  }

  "addSecurityBuffer" should {
    val builder = new MessageBuilder
    "have minimum of 8 bytes" >> { builder.addSecurityBuffer(Array()).toArray.length mustEqual 8 }
    "set the proper length" >> {
      "when the array is 0 length" >> { builder.addSecurityBuffer(Array()).toArray take 2 must matchArray(0, 0) }
      "when the array is non-0 lenght" >> { builder.addSecurityBuffer(Array(1, 2, 3, 4, 5)).toArray take 2 must matchArray(5, 0) }
    }
    "set the proper buffer size" >> {
      "when the array is 0 length" >> { builder.addSecurityBuffer(Array()).toArray drop 2 take 2 must matchArray(0, 0) }
      "when the array is non-0 length" >> { builder.addSecurityBuffer(Array(1, 2, 3, 4, 5)).toArray drop 2 take 2 must matchArray(5, 0) }
    }
    "set the proper offset" >> {
      "when there is nothing following" >> { builder.addSecurityBuffer(Array()).toArray drop 4 take 4 must matchArray(8, 0, 0, 0) }
      "when there is something following" >> { builder.addSecurityBuffer(Array()).addInt(1).toArray drop 4 take 4 must matchArray(12, 0, 0, 0) }
    }
  }
}
