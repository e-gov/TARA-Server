package ee.ria.sso.flow.action;

import ee.ria.sso.service.mobileid.MobileIDAuthenticationService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;


@RunWith(SpringJUnit4ClassRunner.class)
public class MobileIdCheckAuthenticationActionTest extends AbstractAuthenticationActionTest {

    @Mock
    MobileIDAuthenticationService mobileIdService;

    @InjectMocks
    MobileIDCheckAuthenticationAction action;

    @Test
    public void success() throws Exception {
        getAction().doExecute(requestContext);
        verify(mobileIdService).checkLoginForMobileID(eq(requestContext));
    }

    @Override
    AbstractAuthenticationAction getAction() {
        return action;
    }
}
