package ee.ria.sso.flow.action;

import org.springframework.stereotype.Component;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;

@Component("LoginCallbackAction")
public class LoginCallbackAction extends AbstractAction {

    @Override
    protected Event doExecute(RequestContext context) {
        HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getNativeRequest();
        if (isSamlResponse(request)) {
            return new Event(this, "eidasCallback");
        } else if (isBanklinkResponse(request)) {
            return new Event(this, "bankCallback");
        }
        return new Event(this, "login");
    }

    private boolean isBanklinkResponse(HttpServletRequest request) {
        return request.getParameter("VK_SERVICE") != null;
    }

    private boolean isSamlResponse(HttpServletRequest request) {
        return request.getParameter("SAMLResponse") != null;
    }
}
