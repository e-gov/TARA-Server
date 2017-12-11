package org.pac4j.http.client.direct;

import org.pac4j.core.client.DirectClient;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.credentials.extractor.BasicAuthExtractor;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.creator.ProfileCreator;

import ee.ria.sso.authentication.TaraCredentialsException;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class DirectBasicAuthClient extends DirectClient<UsernamePasswordCredentials, CommonProfile> {

    public DirectBasicAuthClient() {
    }

    public DirectBasicAuthClient(Authenticator usernamePasswordAuthenticator) {
        this.defaultAuthenticator(usernamePasswordAuthenticator);
    }

    public DirectBasicAuthClient(Authenticator usernamePasswordAuthenticator, ProfileCreator profileCreator) {
        this.defaultAuthenticator(usernamePasswordAuthenticator);
        this.defaultProfileCreator(profileCreator);
    }

    /*
     * RESTRICTED METHODS
     */

    @Override
    protected UsernamePasswordCredentials retrieveCredentials(WebContext context) throws HttpAction {
        try {
            UsernamePasswordCredentials credentials = this.getCredentialsExtractor().extract(context);
            if (credentials == null) {
                return null;
            } else {
                this.getAuthenticator().validate(credentials, context);
                return credentials;
            }
        } catch (CredentialsException e) {
            throw new TaraCredentialsException("Failed to retrieve or validate credentials", e);
        }
    }

    protected void clientInit(WebContext context) {
        this.defaultCredentialsExtractor(new BasicAuthExtractor(this.getName()));
    }

}
