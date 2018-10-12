package ee.ria.sso.flow.action;

import ee.ria.sso.service.smartid.SmartIDAuthenticationService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;


@RunWith(SpringJUnit4ClassRunner.class)
public class SmartIdCheckAuthenticationActionTest extends AbstractAuthenticationActionTest {

    @Mock
    SmartIDAuthenticationService smartIDAuthenticationService;

    @InjectMocks
    SmartIDCheckAuthenticationAction action;

    @Test
    public void success() throws Exception {
        getAction().doExecute(requestContext);
        verify(smartIDAuthenticationService).checkSmartIdAuthenticationSessionStatus(eq(requestContext));
    }

    @Override
    AbstractAuthenticationAction getAction() {
        return action;
    }
}
