package org.no.ip.bca.jwebunit.scala

import org.apache.commons.httpclient.auth.JCIFSEngine
import org.apache.http.auth.AuthSchemeFactory
import org.apache.http.impl.auth.NTLMScheme
import org.apache.http.params.HttpParams

class NTLMSchemeFactory extends AuthSchemeFactory {
    override def newInstance(params: HttpParams) = new NTLMScheme(new JCIFSEngine())
}
