package ee.ria.sso.service.idcard;

import ee.ria.sso.Constants;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.test.SimpleTestAppender;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.web.servlet.ModelAndView;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import static ee.ria.sso.service.idcard.IDCardController.HEADER_SSL_CLIENT_CERT;
import static org.hamcrest.Matchers.containsString;

public class IDCardControllerTest {

    private StatisticsHandler statistics = new StatisticsHandler();
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss");

    public static final String X509_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGRDCCBCygAwIBAgIQFRkmAJhm0EFZ3Lplb5xtuzANBgkqhkiG9w0BAQsFADBr\n" +
            "MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1\n" +
            "czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHzAdBgNVBAMMFlRFU1Qgb2YgRVNU\n" +
            "RUlELVNLIDIwMTUwHhcNMTcxMDEwMTIxNzQxWhcNMjIxMDA5MjA1OTU5WjCBmzEL\n" +
            "MAkGA1UEBhMCRUUxDzANBgNVBAoMBkVTVEVJRDEXMBUGA1UECwwOYXV0aGVudGlj\n" +
            "YXRpb24xJjAkBgNVBAMMHU3DhE5OSUssTUFSSS1MSUlTLDQ3MTAxMDEwMDMzMRAw\n" +
            "DgYDVQQEDAdNw4ROTklLMRIwEAYDVQQqDAlNQVJJLUxJSVMxFDASBgNVBAUTCzQ3\n" +
            "MTAxMDEwMDMzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEVAcrw263vwciSE9i5rP2\n" +
            "3NJq2YqKo8+fk9kSDIflVJICplDiN9lz5uh69ICfygyxmwgLB3m8opoAfSTOdkGI\n" +
            "SyLR7E/76AppfdWQe7NO0YV2DZrEA4FU3xNGotfJNOrAo4ICXzCCAlswCQYDVR0T\n" +
            "BAIwADAOBgNVHQ8BAf8EBAMCA4gwgYkGA1UdIASBgTB/MHMGCSsGAQQBzh8DATBm\n" +
            "MC8GCCsGAQUFBwIBFiNodHRwczovL3d3dy5zay5lZS9yZXBvc2l0b29yaXVtL0NQ\n" +
            "UzAzBggrBgEFBQcCAjAnDCVBaW51bHQgdGVzdGltaXNla3MuIE9ubHkgZm9yIHRl\n" +
            "c3RpbmcuMAgGBgQAj3oBAjAkBgNVHREEHTAbgRltYXJpLWxpaXMubWFubmlrQGVl\n" +
            "c3RpLmVlMB0GA1UdDgQWBBTk9OenGSkT7fZr6ssshuWFSD17VjBhBggrBgEFBQcB\n" +
            "AwRVMFMwUQYGBACORgEFMEcwRRY/aHR0cHM6Ly9zay5lZS9lbi9yZXBvc2l0b3J5\n" +
            "L2NvbmRpdGlvbnMtZm9yLXVzZS1vZi1jZXJ0aWZpY2F0ZXMvEwJFTjAgBgNVHSUB\n" +
            "Af8EFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwHwYDVR0jBBgwFoAUScDyRDll1ZtG\n" +
            "Ow04YIOx1i0ohqYwgYMGCCsGAQUFBwEBBHcwdTAsBggrBgEFBQcwAYYgaHR0cDov\n" +
            "L2FpYS5kZW1vLnNrLmVlL2VzdGVpZDIwMTUwRQYIKwYBBQUHMAKGOWh0dHBzOi8v\n" +
            "c2suZWUvdXBsb2FkL2ZpbGVzL1RFU1Rfb2ZfRVNURUlELVNLXzIwMTUuZGVyLmNy\n" +
            "dDBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vd3d3LnNrLmVlL2NybHMvZXN0ZWlk\n" +
            "L3Rlc3RfZXN0ZWlkMjAxNS5jcmwwDQYJKoZIhvcNAQELBQADggIBALhg4bhXry4H\n" +
            "376mvyZhMYulobeFAdts9JQYWk5de2+lZZiTcX2yHbAF80DlW1LZe9NczCbF991o\n" +
            "5ZBYP80Tzc+42urBeUesydVEkB+9Qzv/d3+eCU//jN4seoeIyxfSP32JJefgT3V+\n" +
            "u2dkvTPx5HLz3gfptQ7L6usNY5hCxxcxtxW/zKj28qKLH3cQlryZbAxLy+C3aIDD\n" +
            "tlf/OPLWFDZt3bDogehCGYdgwsAz7pur1gKn7UXOnFX+Na5zGQPPgyH+nwgby3Zs\n" +
            "GC8Hy4K4I98q+wcfykJnbT/jtTZBROOiS8br27oLEYgVY9iaTyL92arvLSQHc2jW\n" +
            "MwDQFptJtCnMvJbbuo31Mtg0nw1kqCmqPQLyMLRAFpxRxXOrOCArmPET6u4i9VYm\n" +
            "e5M5uuwS4BmnnZTmDbkLz/1kMqbYc7QRynsh7Af7oVI15qP3iELtMWLWVHafpE+q\n" +
            "YWOE2nwbnlKjt6HGsGno6gcrnOYhlO6/VXfNLPfvZn0OHGiAT1v6YyFQyeYxqfGF\n" +
            "0OxAOt06wDLEBd7p9cuPHuu8OxuLO0478YXyWdwWeHbJgthAlbaTKih+jW4Cahsc\n" +
            "0kpQarrExgPQ00aInw1tVifbEYcRhB25YOiIDlSPORenQ+SdkT6OyU3wJ8rArBs4\n" +
            "OfEkPnSsNkNa+PeTPPpPZ1LgmhoczuQ3\n" +
            "-----END CERTIFICATE-----";

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Before @After
    public void cleanUp() {
        SimpleTestAppender.events.clear();
    }

    @Test
    public void certificateHeaderNotFoundInRequest() throws Exception {

        ModelAndView response = new IDCardController(statistics).handleRequest(new MockHttpServletRequest());

        Assert.assertEquals(new Boolean(false),response.getModel().get("ok"));
        SimpleTestAppender.verifyLogEventsExistInOrder(
                containsString("ID-Card controller error: Expected header '" + HEADER_SSL_CLIENT_CERT + "' could not be found in request")
        );
    }

    @Test
    public void certificateHeaderEmptyInRequest() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HEADER_SSL_CLIENT_CERT, "");

        ModelAndView response = new IDCardController(statistics).handleRequest(request);

        Assert.assertEquals(new Boolean(false),response.getModel().get("ok"));
        SimpleTestAppender.verifyLogEventsExistInOrder(
                containsString("ID-Card controller error: Unable to find certificate from request")
        );
    }

    @Test
    public void invalidCertificateHeaderInRequest() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HEADER_SSL_CLIENT_CERT, "dGVzdA==");

        ModelAndView response = new IDCardController(statistics).handleRequest(request);

        Assert.assertEquals(new Boolean(false),response.getModel().get("ok"));
        SimpleTestAppender.verifyLogEventsExistInOrder(
                containsString("ID-Card controller error: Failed to decode certificate")
        );
    }

    @Test
    public void okWithExistingSession() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HEADER_SSL_CLIENT_CERT, X509_CERT);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(Constants.TARA_OIDC_SESSION_CLIENT_ID, "openIdDemo");
        request.setSession(session);

        ModelAndView response = new IDCardController(statistics).handleRequest(request);
        Assert.assertEquals(true, response.getModel().get("ok"));
        Assert.assertTrue("Old session must be invalidated!", session.isInvalid());

        SimpleTestAppender.verifyLogEventsExistInOrder(
                containsString("ID-Card certificate stored in renewed user session"),
                containsString(String.format("%s;%s;%s;%s;", formatter.format(LocalDateTime.now()), request.getSession().getAttribute(Constants.TARA_OIDC_SESSION_CLIENT_ID), AuthenticationType.IDCard, StatisticsOperation.START_AUTH))
        );
    }

    @Test
    public void shouldFailWithNoExistingSession() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HEADER_SSL_CLIENT_CERT, X509_CERT);
        request.setSession(null);

        ModelAndView response = new IDCardController(statistics).handleRequest(request);
        Assert.assertEquals(false, response.getModel().get("ok"));
        SimpleTestAppender.verifyLogEventsExistInOrder(
                containsString("ID-Card certificate stored in new user session"),
                containsString("ID-Card controller error: Client-ID cannot be null!")
        );
    }
}
