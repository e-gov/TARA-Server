package org.pac4j.core.credentials.extractor;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.exception.HttpAction;

import ee.ria.sso.utils.HashingUtil;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class BasicAuthExtractor implements CredentialsExtractor<UsernamePasswordCredentials> {

    private final HeaderExtractor extractor;
    private final String clientName;

    public BasicAuthExtractor(String clientName) {
        this("Authorization", "Basic ", clientName);
    }

    public BasicAuthExtractor(String headerName, String prefixHeader, String clientName) {
        this.extractor = new HeaderExtractor(headerName, prefixHeader, clientName);
        this.clientName = clientName;
    }

    public UsernamePasswordCredentials extract(WebContext context) throws HttpAction, CredentialsException {
        TokenCredentials credentials = this.extractor.extract(context);
        if (credentials == null) {
            return null;
        } else {
            byte[] decoded = Base64.getDecoder().decode(credentials.getToken());
            String token;
            try {
                token = new String(decoded, "UTF-8");
            } catch (UnsupportedEncodingException var6) {
                throw new CredentialsException("Bad format of the basic auth header");
            }
            int delim = token.indexOf(":");
            if (delim < 0) {
                throw new CredentialsException("Bad format of the basic auth header");
            } else {
                return new UsernamePasswordCredentials(token.substring(0, delim), HashingUtil.hash(token.substring(delim + 1)), this.clientName);
            }
        }
    }

}
