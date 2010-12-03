package org.no.ip.bca.jwebunit.scala

import com.gargoylesoftware.htmlunit.HttpWebConnection
import com.gargoylesoftware.htmlunit.WebClient
import org.apache.http.impl.client.AbstractHttpClient
import org.apache.http.auth.AuthScope

class NtlmWebConnection(wc: WebClient) extends HttpWebConnection(wc) {
    override protected def createHttpClient(): AbstractHttpClient = {
        val provider = wc.getCredentialsProvider
        val creds = provider.getCredentials(new AuthScope("", AuthScope.ANY_PORT))
        if (creds != null) {
            provider.setCredentials(new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT), creds)
        }
        
        val client = super.createHttpClient
        client.getAuthSchemes.register("ntlm", new NTLMSchemeFactory())
        client
    }
}