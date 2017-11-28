package org.pac4j.core.engine;

import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.pac4j.core.authorization.checker.AuthorizationChecker;
import org.pac4j.core.authorization.checker.DefaultAuthorizationChecker;
import org.pac4j.core.client.Client;
import org.pac4j.core.client.Clients;
import org.pac4j.core.client.DirectClient;
import org.pac4j.core.client.IndirectClient;
import org.pac4j.core.client.direct.AnonymousClient;
import org.pac4j.core.client.finder.ClientFinder;
import org.pac4j.core.client.finder.DefaultClientFinder;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.http.HttpActionAdapter;
import org.pac4j.core.matching.DefaultMatchingChecker;
import org.pac4j.core.matching.MatchingChecker;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.ProfileManagerFactoryAware;
import org.pac4j.core.util.CommonHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class DefaultSecurityLogic<R, C extends WebContext> extends ProfileManagerFactoryAware<C> implements SecurityLogic<R, C> {

    protected Logger logger = LoggerFactory.getLogger(this.getClass());
    private ClientFinder clientFinder = new DefaultClientFinder();
    private AuthorizationChecker authorizationChecker = new DefaultAuthorizationChecker();
    private MatchingChecker matchingChecker = new DefaultMatchingChecker();
    private boolean saveProfileInSession;

    public DefaultSecurityLogic() {
    }

    public R perform(C context, Config config, SecurityGrantedAccessAdapter<R, C> securityGrantedAccessAdapter, HttpActionAdapter<R, C> httpActionAdapter, String clients, String authorizers, String matchers, Boolean inputMultiProfile, Object... parameters) {
        this.logger.debug("=== SECURITY ===");
        boolean multiProfile;
        if (inputMultiProfile == null) {
            multiProfile = false;
        } else {
            multiProfile = inputMultiProfile.booleanValue();
        }
        CommonHelper.assertNotNull("context", context);
        CommonHelper.assertNotNull("config", config);
        CommonHelper.assertNotNull("httpActionAdapter", httpActionAdapter);
        CommonHelper.assertNotNull("clientFinder", this.clientFinder);
        CommonHelper.assertNotNull("authorizationChecker", this.authorizationChecker);
        CommonHelper.assertNotNull("matchingChecker", this.matchingChecker);
        Clients configClients = config.getClients();
        CommonHelper.assertNotNull("configClients", configClients);
        // TODO is it most appropriate place for this code
        String language = context.getRequestParameter("lang");
        if (Arrays.asList("et", "en", "ru").contains(language)) {
            this.logger.debug("Setting locale from 'lang' parameter to [{}]", language);
            context.setSessionAttribute("org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE", new Locale(language));
        }
        HttpAction action;
        try {
            this.logger.debug("url: {}", context.getFullRequestURL());
            this.logger.debug("matchers: {}", matchers);
            if (!this.matchingChecker.matches(context, matchers, config.getMatchers())) {
                this.logger.debug("no matching for this request -> grant access");
                return securityGrantedAccessAdapter.adapt(context, parameters);
            } else if (!this.validateOIDCRequest(context)) {
                return httpActionAdapter.adapt(HttpAction.status("", 403, context).getCode(), context);
            }
            this.logger.debug("clients: {}", clients);
            List<Client> currentClients = this.clientFinder.find(configClients, context, clients);
            this.logger.debug("currentClients: {}", currentClients);
            boolean loadProfilesFromSession = this.loadProfilesFromSession(context, currentClients);
            this.logger.debug("loadProfilesFromSession: {}", loadProfilesFromSession);
            ProfileManager manager = this.getProfileManager(context, config);
            List<CommonProfile> profiles = manager.getAll(loadProfilesFromSession);
            this.logger.debug("profiles: {}", profiles);
            if (CommonHelper.isEmpty(profiles) && CommonHelper.isNotEmpty(currentClients)) {
                boolean updated = false;
                Iterator var18 = currentClients.iterator();
                while (var18.hasNext()) {
                    Client currentClient = (Client) var18.next();
                    if (currentClient instanceof DirectClient) {
                        this.logger.debug("Performing authentication for direct client: {}", currentClient);
                        Credentials credentials = currentClient.getCredentials(context);
                        this.logger.debug("credentials: {}", credentials);
                        CommonProfile profile = currentClient.getUserProfile(credentials, context);
                        this.logger.debug("profile: {}", profile);
                        if (profile != null) {
                            boolean saveProfileInSession = this.saveProfileInSession(context, currentClients, (DirectClient) currentClient, profile);
                            this.logger.debug("saveProfileInSession: {} / multiProfile: {}", saveProfileInSession, multiProfile);
                            manager.save(saveProfileInSession, profile, multiProfile);
                            updated = true;
                            if (!multiProfile) {
                                break;
                            }
                        }
                    }
                }
                if (updated) {
                    profiles = manager.getAll(loadProfilesFromSession);
                    this.logger.debug("new profiles: {}", profiles);
                }
            }
            if (CommonHelper.isNotEmpty(profiles)) {
                this.logger.debug("authorizers: {}", authorizers);
                if (this.authorizationChecker.isAuthorized(context, profiles, authorizers, config.getAuthorizers())) {
                    this.logger.debug("authenticated and authorized -> grant access");
                    return securityGrantedAccessAdapter.adapt(context, parameters);
                }
                this.logger.debug("forbidden");
                action = this.forbidden(context, currentClients, profiles, authorizers);
            } else if (this.startAuthentication(context, currentClients)) {
                this.logger.debug("Starting authentication");
                this.saveRequestedUrl(context, currentClients);
                action = this.redirectToIdentityProvider(context, currentClients);
            } else {
                this.logger.debug("unauthorized");
                action = this.unauthorized(context, currentClients);
            }
        } catch (HttpAction var23) {
            this.logger.debug("extra HTTP action required in security: {}", var23.getCode());
            action = var23;
        } catch (TechnicalException var24) {
            throw var24;
        } catch (Throwable var25) {
            throw new TechnicalException(var25);
        }
        return httpActionAdapter.adapt(action.getCode(), context);
    }

    protected boolean loadProfilesFromSession(C context, List<Client> currentClients) {
        return CommonHelper.isEmpty(currentClients) || currentClients.get(0) instanceof IndirectClient || currentClients.get(0) instanceof AnonymousClient;
    }

    protected boolean saveProfileInSession(C context, List<Client> currentClients, DirectClient directClient, CommonProfile profile) {
        return this.saveProfileInSession;
    }

    protected HttpAction forbidden(C context, List<Client> currentClients, List<CommonProfile> profiles, String authorizers) throws HttpAction {
        return HttpAction.forbidden("forbidden", context);
    }

    protected boolean startAuthentication(C context, List<Client> currentClients) {
        return CommonHelper.isNotEmpty(currentClients) && currentClients.get(0) instanceof IndirectClient;
    }

    protected void saveRequestedUrl(C context, List<Client> currentClients) throws HttpAction {
        String requestedUrl = context.getFullRequestURL();
        this.logger.debug("requestedUrl: {}", requestedUrl);
        context.setSessionAttribute("pac4jRequestedUrl", requestedUrl);
    }

    protected HttpAction redirectToIdentityProvider(C context, List<Client> currentClients) throws HttpAction {
        IndirectClient currentClient = (IndirectClient) currentClients.get(0);
        return currentClient.redirect(context);
    }

    protected HttpAction unauthorized(C context, List<Client> currentClients) throws HttpAction {
        return HttpAction.unauthorized("unauthorized", context, (String) null);
    }

    private boolean validateOIDCRequest(C context) {
        if (context.getPath().equals("/oidc/authorize")) {
            Collection<String> scopes = OAuth20Utils.getRequestedScopes((J2EContext) context);
            if (scopes.isEmpty() || !scopes.contains("openid")) {
                this.logger.error(String.format("Provided scopes [%s] are undefined by OpenID Connect, which requires that scope [%s] MUST be specified. CAS DO NOT allow this request to be processed for now", scopes, "openid"));
                return false;
            }
        }
        return true;
    }

    public ClientFinder getClientFinder() {
        return this.clientFinder;
    }

    public void setClientFinder(ClientFinder clientFinder) {
        this.clientFinder = clientFinder;
    }

    public AuthorizationChecker getAuthorizationChecker() {
        return this.authorizationChecker;
    }

    public void setAuthorizationChecker(AuthorizationChecker authorizationChecker) {
        this.authorizationChecker = authorizationChecker;
    }

    public MatchingChecker getMatchingChecker() {
        return this.matchingChecker;
    }

    public void setMatchingChecker(MatchingChecker matchingChecker) {
        this.matchingChecker = matchingChecker;
    }

    public boolean isSaveProfileInSession() {
        return this.saveProfileInSession;
    }

    public void setSaveProfileInSession(boolean saveProfileInSession) {
        this.saveProfileInSession = saveProfileInSession;
    }

}
