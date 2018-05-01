package ee.ria.sso.flow.action;

import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;

@Component("EIDASCallbackAction")
public class EidasCallbackAction extends AbstractAuthenticationAction {

    @Override
    protected Event doAuthenticationExecute(RequestContext context) {
        HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getNativeRequest();
        if (request.getParameter("SAMLResponse") != null) {
            return new Event(this, "eidasCallback");
        }
        return new Event(this, "login");
    }

}
