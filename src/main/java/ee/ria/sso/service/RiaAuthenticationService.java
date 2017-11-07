package ee.ria.sso.service;

import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public interface RiaAuthenticationService {

    Event loginByIDCard(RequestContext context);

    Event startLoginByMobileID(RequestContext context);

    Event checkLoginForMobileID(RequestContext context);

}
