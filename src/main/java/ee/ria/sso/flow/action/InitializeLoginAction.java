package ee.ria.sso.flow.action;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.credential.PreAuthenticationCredential;
import ee.ria.sso.oidc.TaraScope;
import ee.ria.sso.oidc.TaraScopeValuedAttribute;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.springframework.stereotype.Component;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;

@Component("InitializeLoginAction")
public class InitializeLoginAction extends AbstractAction {

    @Override
    protected Event doExecute(RequestContext context) {
        HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getNativeRequest();
        if (isEidasOnlyAuthenticationForSpecificCountry(request, context)) {
            return new Event(this, "directEidasLogin");
        }
        return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
    }
    
    private boolean isEidasOnlyAuthenticationForSpecificCountry(HttpServletRequest request, RequestContext context) {
        HttpSession session = request.getSession(false);
        Object scopeAttributes = session.getAttribute(Constants.TARA_OIDC_SESSION_SCOPES);
        if (scopeAttributes == null) {
            return false;
        }
        boolean isEidasOnly = ((List<TaraScope>) scopeAttributes).contains(TaraScope.EIDASONLY);
        return isEidasOnly && isEidasCountryAttributePresent(session, context);
    }

    private boolean isEidasCountryAttributePresent(HttpSession session, RequestContext context) {
        Object eidasCountryAttribute = session.getAttribute(Constants.TARA_OIDC_SESSION_SCOPE_EIDAS_COUNTRY);
        if (eidasCountryAttribute == null) {
            return false;
        }

        setContextAuthCredential(context, (TaraScopeValuedAttribute) eidasCountryAttribute);
        return true;
    }

    private void setContextAuthCredential(RequestContext context, TaraScopeValuedAttribute eidasCountryAttribute) {
        PreAuthenticationCredential authCredential = (PreAuthenticationCredential) context.getFlowScope().get("credential");
        authCredential.setCountry(eidasCountryAttribute.getValue().toUpperCase());

    }
}
