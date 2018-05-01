package ee.ria.sso.flow.action;

import org.springframework.stereotype.Component;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@Component("EIDASKeepAliveAuthenticationAction")
public class EidasKeepAliveAuthenticationAction extends AbstractAction {

    @Override
    protected Event doExecute(RequestContext context) {
        return null;
    }

}
