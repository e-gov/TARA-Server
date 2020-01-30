package ee.ria.sso.flow.action;

import ee.ria.sso.service.mobileid.MobileIDAuthenticationService;
import ee.ria.sso.service.smartid.SmartIDAuthenticationService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

@RunWith(SpringJUnit4ClassRunner.class)
public class MobileIdCheckCancelActionTest extends AbstractAuthenticationActionTest {

    @Mock
    MobileIDAuthenticationService mobileIDAuthenticationService;

    @InjectMocks
    MobileIDCheckCancelAction action;

    @Test
    public void successfulExecutionTest() throws Exception {
        getAction().doExecute(requestContext);
        verify(mobileIDAuthenticationService).cancelAuthenticationSessionStatusChecking(eq(requestContext));
    }

    @Override
    AbstractAuthenticationAction getAction() {
        return action;
    }
}
