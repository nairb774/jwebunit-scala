package org.no.ip.bca.jwebunit.scala;

import java.io.IOException;

import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.util.Base64;

import org.apache.http.impl.auth.NTLMEngine;
import org.apache.http.impl.auth.NTLMEngineException;

public class JCIFSEngine implements NTLMEngine {
    public String generateType1Msg(final String domain, final String workstation) throws NTLMEngineException {
        return Base64.encode(new Type1Message(Type1Message.getDefaultFlags(), domain, workstation).toByteArray());
    }

    public String generateType3Msg(final String username, final String password, final String domain,
            final String workstation, final String challenge) throws NTLMEngineException {
        final Type2Message type2Message;
        try {
            type2Message = new Type2Message(Base64.decode(challenge));
        } catch (final IOException ex) {
            throw new NTLMEngineException("Invalid Type2Message", ex);
        }
        return Base64.encode(new Type3Message(type2Message, password, domain, username, workstation,
                Type3Message.getDefaultFlags()).toByteArray());
    }
}
