package ee.ria.sso.logging;

import ee.ria.sso.oidc.MockPrincipalUtils;
import org.apereo.cas.authentication.principal.SimpleWebApplicationServiceImpl;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.ticket.accesstoken.AccessTokenImpl;
import org.apereo.cas.ticket.support.NeverExpiresExpirationPolicy;
import org.aspectj.lang.JoinPoint;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public class OAuth20UserProfileDataAuditResourceResolverTest {


    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void resolveShouldSucceed() {

        Map<String, Object> jsonMap = new LinkedHashMap<>();
        jsonMap.put("param1", "value1");
        jsonMap.put("param2", true);
        jsonMap.put("param3", Arrays.asList("value3"));

        AccessToken accessToken = getMockAccessToken("AT-123-u0lhxUZbLpkkGFfgM5fUadzcmC-f7uU9");
        JoinPoint joinPoint = Mockito.mock(JoinPoint.class);
        Mockito.when(joinPoint.getArgs()).thenReturn(new Object[] {accessToken});

        String[] result = new UserInfoAuditResourceResolver().resolveFrom(joinPoint, jsonMap);

        Assert.assertArrayEquals(new String[]{"[" +
                "access_token=AT-**************************zcmC-f7uU9," +
                "scopes=[openid, idcard, email]," +
                "claims={param1=value1, param2=true, param3=[value3]}]"}, result);
    }

    @Test
    public void resolveFromModelShouldFailWhenNull() {

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("User profile data must not be null");

        JoinPoint joinPoint = Mockito.mock(JoinPoint.class);
        Mockito.when(joinPoint.getArgs()).thenReturn(new Object[] {"ok"});

        String[] result = new UserInfoAuditResourceResolver().resolveFrom(joinPoint, (Object)null);
    }

    @Test
    public void resolveFromExceptionWithoutMessage() {

        JoinPoint joinPoint = Mockito.mock(JoinPoint.class);
        Mockito.when(joinPoint.getArgs()).thenReturn(new Object[] {"ok"});

        String[] result = new UserInfoAuditResourceResolver().resolveFrom(joinPoint, new RuntimeException());
        Assert.assertArrayEquals(new String[]{"java.lang.RuntimeException"}, result);
    }

    @Test
    public void resolveFromExceptionWithMessage() {

        JoinPoint joinPoint = Mockito.mock(JoinPoint.class);
        Mockito.when(joinPoint.getArgs()).thenReturn(new Object[] {"ok"});

        String[] result = new UserInfoAuditResourceResolver().resolveFrom(joinPoint, new RuntimeException("Something bad happened!"));
        Assert.assertArrayEquals(new String[]{"Something bad happened!"}, result);
    }

    private AccessTokenImpl getMockAccessToken(String id) {
        return new AccessTokenImpl(id, new SimpleWebApplicationServiceImpl(), MockPrincipalUtils.getMockBasicAuthentication(), new NeverExpiresExpirationPolicy(), MockPrincipalUtils.getMockUserAuthentication(MockPrincipalUtils.getMockEidasAuthPrincipalAttributes()), Arrays.asList("openid", "idcard", "email"));
    }
}
