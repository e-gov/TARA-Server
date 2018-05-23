package org.pac4j.core.engine;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.validators.TaraScope;
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

import ee.ria.sso.authentication.TaraCredentialsException;
import ee.ria.sso.flow.JSONFlowExecutionException;
import ee.ria.sso.validators.OIDCRequestValidator;
import ee.ria.sso.validators.RequestParameter;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class DefaultSecurityLogic<R, C extends WebContext> extends ProfileManagerFactoryAware<C> implements SecurityLogic<R, C> {

    protected Logger log = LoggerFactory.getLogger(this.getClass());
    private ClientFinder clientFinder = new DefaultClientFinder();
    private AuthorizationChecker authorizationChecker = new DefaultAuthorizationChecker();
    private MatchingChecker matchingChecker = new DefaultMatchingChecker();
    private boolean saveProfileInSession;

    public DefaultSecurityLogic() {
    }

    public R perform(C context, Config config, SecurityGrantedAccessAdapter<R, C> securityGrantedAccessAdapter, HttpActionAdapter<R, C> httpActionAdapter, String clients, String authorizers, String matchers, Boolean inputMultiProfile, Object... parameters) {
        this.log.debug("=== SECURITY ===");
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
            this.log.debug("Setting locale from 'lang' parameter to [{}]", language);
            context.setSessionAttribute("org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE", new Locale(language));
        }
        HttpAction action;
        try {
            this.log.debug("url: {}", context.getFullRequestURL());
            this.log.debug("matchers: {}", matchers);
            if (!this.matchingChecker.matches(context, matchers, config.getMatchers())) {
                this.log.debug("no matching for this request -> grant access");
                return securityGrantedAccessAdapter.adapt(context, parameters);
            }
            // Validating OAuth 2.0 Authorization request according to RFC6749
            Optional<Integer> errorCode = this.validateOIDCRequest(context);
            if (errorCode.isPresent()) {
                return httpActionAdapter.adapt(errorCode.get(), context);
            }
            this.log.debug("clients: {}", clients);
            List<Client> currentClients = this.clientFinder.find(configClients, context, clients);
            this.log.debug("currentClients: {}", currentClients);
            boolean loadProfilesFromSession = this.loadProfilesFromSession(context, currentClients);
            this.log.debug("loadProfilesFromSession: {}", loadProfilesFromSession);
            ProfileManager manager = this.getProfileManager(context, config);
            List<CommonProfile> profiles = manager.getAll(loadProfilesFromSession);
            this.log.debug("profiles: {}", profiles);
            if (CommonHelper.isEmpty(profiles) && CommonHelper.isNotEmpty(currentClients)) {
                boolean updated = false;
                Iterator var18 = currentClients.iterator();
                while (var18.hasNext()) {
                    Client currentClient = (Client) var18.next();
                    if (currentClient instanceof DirectClient) {
                        this.log.debug("Performing authentication for direct client: {}", currentClient);
                        Credentials credentials = currentClient.getCredentials(context);
                        this.log.debug("credentials: {}", credentials);
                        CommonProfile profile = currentClient.getUserProfile(credentials, context);
                        this.log.debug("profile: {}", profile);
                        if (profile != null) {
                            boolean saveProfileInSession = this.saveProfileInSession(context, currentClients, (DirectClient) currentClient, profile);
                            this.log.debug("saveProfileInSession: {} / multiProfile: {}", saveProfileInSession, multiProfile);
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
                    this.log.debug("new profiles: {}", profiles);
                }
            }
            if (CommonHelper.isNotEmpty(profiles)) {
                this.log.debug("authorizers: {}", authorizers);
                if (this.authorizationChecker.isAuthorized(context, profiles, authorizers, config.getAuthorizers())) {
                    this.log.debug("authenticated and authorized -> grant access");
                    return securityGrantedAccessAdapter.adapt(context, parameters);
                }
                this.log.debug("forbidden");
                action = this.forbidden(context, currentClients, profiles, authorizers);
            } else if (this.startAuthentication(context, currentClients)) {
                this.log.debug("Starting authentication");
                this.saveRequestedUrl(context, currentClients);
                this.saveAllowedAuthenticationMethods(context);
                this.saveLevelOfAssuranceIfPresent(context);
                action = this.redirectToIdentityProvider(context, currentClients);
            } else {
                this.log.debug("unauthorized");
                action = this.unauthorized(context, currentClients);
            }
        } catch (HttpAction var23) {
            this.log.debug("extra HTTP action required in security: {}", var23.getCode());
            action = var23;
        } catch (TaraCredentialsException e) {
            throw JSONFlowExecutionException.ofUnauthorized(Collections.singletonMap("error", e.getError()), e);
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
        this.log.debug("requestedUrl: {}", requestedUrl);
        context.setSessionAttribute("pac4jRequestedUrl", requestedUrl);
    }

    protected void saveAllowedAuthenticationMethods(C context) {
        String scope = context.getRequestParameter(RequestParameter.SCOPE.name().toLowerCase());
        List scopes = Arrays.stream(scope.split(" ")).collect(Collectors.toList());

        List<String> authenticationMethods = scopes.contains(TaraScope.EIDASONLY.getFormalName()) ? Arrays.asList(AuthenticationType.eIDAS.name()) :
                Arrays.asList(AuthenticationType.IDCard.name(), AuthenticationType.MobileID.name(), AuthenticationType.eIDAS.name());
        context.setSessionAttribute("taraAuthenticationMethods", authenticationMethods);
    }

    protected void saveLevelOfAssuranceIfPresent(C context) {
        String acrValues = context.getRequestParameter(RequestParameter.ACR_VALUES.getParameterKey());
        if (acrValues == null) return;

        this.log.debug("acr_values: {}", acrValues);

        LevelOfAssurance loa = LevelOfAssurance.findByAcrName(acrValues);
        context.setSessionAttribute("taraAuthorizeRequestLevelOfAssurance", loa);
    }

    protected HttpAction redirectToIdentityProvider(C context, List<Client> currentClients) throws HttpAction {
        IndirectClient currentClient = (IndirectClient) currentClients.get(0);
        return currentClient.redirect(context);
    }

    protected HttpAction unauthorized(C context, List<Client> currentClients) throws HttpAction {
        return HttpAction.unauthorized("unauthorized", context, (String) null);
    }

    private Optional<Integer> validateOIDCRequest(C context) {
        if (context.getPath().equals("/oidc/authorize")) {
            return OIDCRequestValidator.validateAll((J2EContext) context, Arrays.asList(RequestParameter.values()));
        }
        return Optional.empty();
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
