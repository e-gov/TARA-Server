package ee.ria.sso.flow.action;

import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;

@Component("LoginCallbackAction")
public class LoginCallbackAction extends AbstractAuthenticationAction {

    @Override
    protected Event doAuthenticationExecute(RequestContext context) {
        HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getNativeRequest();
        if (request.getParameter("SAMLResponse") != null) {
            return new Event(this, "eidasCallback");
        } else if (request.getParameter("VK_SERVICE") != null) {
            return new Event(this, "bankCallback");
        }
        return new Event(this, "login");
    }

}
