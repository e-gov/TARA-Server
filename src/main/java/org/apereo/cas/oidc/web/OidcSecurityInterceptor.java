package org.apereo.cas.oidc.web;

import ee.ria.sso.config.TaraProperties;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.util.OidcAuthorizationRequestSupport;
import org.apereo.cas.util.Pac4jUtils;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.springframework.web.SecurityInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;
import java.util.Set;


@Slf4j
public class OidcSecurityInterceptor extends SecurityInterceptor {

    public static final String OIDC_AUTHORIZE_VISIT_COUNT = "noOfVisits";
    private final OidcAuthorizationRequestSupport authorizationRequestSupport;
    private final TaraProperties taraProperties;

    public OidcSecurityInterceptor(final TaraProperties taraProperties, final Config config, final String name, final OidcAuthorizationRequestSupport support) {
        super(config, name);
        this.authorizationRequestSupport = support;
        this.taraProperties = taraProperties;
    }

    @Override
    public boolean preHandle(final HttpServletRequest request,
                             final HttpServletResponse response,
                             final Object handler) throws Exception {

        final J2EContext ctx = Pac4jUtils.getPac4jJ2EContext(request, response);
        final ProfileManager manager = Pac4jUtils.getPac4jProfileManager(request, response);

        boolean clearCreds = false;

        int visitCount = getVisitCount(ctx);

        final Optional<Authentication> authentication = authorizationRequestSupport.isCasAuthenticationAvailable(ctx);
        if (!authentication.isPresent()) {
            clearCreds = true;
        }

        final Optional<UserProfile> auth = authorizationRequestSupport.isAuthenticationProfileAvailable(ctx);

        if (auth.isPresent()) {
            final Optional<Long> maxAge = authorizationRequestSupport.getOidcMaxAgeFromAuthorizationRequest(ctx);
            if (maxAge.isPresent()) {
                clearCreds = authorizationRequestSupport.isCasAuthenticationOldForMaxAgeAuthorizationRequest(ctx, auth.get());
            }

            if (taraProperties.isForceOidcAuthenticationRenewalEnabled() && visitCount > 1) {
                clearCreds = true;
            }
        }

        final Set<String> prompts = authorizationRequestSupport.getOidcPromptFromAuthorizationRequest(ctx);

        if (!clearCreds) {
            clearCreds = prompts.contains(OidcConstants.PROMPT_LOGIN);
        }

        if (clearCreds) {
            clearCreds = !prompts.contains(OidcConstants.PROMPT_NONE);
        }

        if (clearCreds) {
            clearCounter(ctx);
            manager.remove(true);
        }
        return super.preHandle(request, response, handler);
    }

    private int getVisitCount(J2EContext ctx) {
        int visitCount = 1;
        if (ctx.getSessionStore().get(ctx, OIDC_AUTHORIZE_VISIT_COUNT) == null) {
            ctx.getSessionStore().set(ctx, OIDC_AUTHORIZE_VISIT_COUNT, visitCount);
        } else {
            visitCount = (Integer) ctx.getSessionStore().get(ctx, OIDC_AUTHORIZE_VISIT_COUNT);
            ctx.getSessionStore().set(ctx, OIDC_AUTHORIZE_VISIT_COUNT, ++visitCount);
        }
        return visitCount;
    }

    private void clearCounter(J2EContext ctx) {
        ctx.getSessionStore().set(ctx, OIDC_AUTHORIZE_VISIT_COUNT, null);
    }
}
