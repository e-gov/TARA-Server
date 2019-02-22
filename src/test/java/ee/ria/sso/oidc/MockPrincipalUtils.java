package ee.ria.sso.oidc;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import org.apereo.cas.authentication.DefaultAuthentication;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.TicketGrantingTicketImpl;
import org.mockito.Mockito;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.sso.authentication.principal.TaraPrincipal.Attribute.*;
import static ee.ria.sso.authentication.principal.TaraPrincipal.Attribute.ACR;
import static ee.ria.sso.authentication.principal.TaraPrincipal.Attribute.DATE_OF_BIRTH;

public class MockPrincipalUtils {

    public static final String MOCK_EMAIL = "givenname.familyname@eesti.ee";
    public static final String MOCK_DATE_OF_BIRTH = "1971-01-01";
    public static final String MOCK_FAMILY_NAME = "Family-Name-ŠÕäÖü";
    public static final String MOCK_GIVEN_NAME = "Given-Name-ŠÕäÖü";
    public static final String MOCK_SUBJECT_CODE_EE = "EE47101010033";
    public static final String MOCK_SUBJECT_CODE_EIDAS = "GR1234567890-abcdefge78789768";
    public static final String NONCE = "1234567890nonce";
    public static final String STATE = "state123abc";
    public static final String TARA_PRINCIPAL_ID = "taraPrincipalId";

    public static HashMap<String, Object> getMockMidAuthPrincipalAttributes() {
        HashMap<String, Object> map = new HashMap<>();
        map.put(SUB.name(), Arrays.asList(MOCK_SUBJECT_CODE_EE));
        map.put(GIVEN_NAME.name(), Arrays.asList(MOCK_GIVEN_NAME));
        map.put(FAMILY_NAME.name(), Arrays.asList(MOCK_FAMILY_NAME));
        map.put(DATE_OF_BIRTH.name(), Arrays.asList(MOCK_DATE_OF_BIRTH));
        map.put(AMR.name(), Arrays.asList(Arrays.asList(AuthenticationType.MobileID.getAmrName())));
        return map;
    }

    public static HashMap<String, Object> getMockIdCardAuthPrincipalAttributes() {
        HashMap<String, Object> map = new HashMap<>();
        map.put(SUB.name(), Arrays.asList(MOCK_SUBJECT_CODE_EE));
        map.put(GIVEN_NAME.name(), Arrays.asList(MOCK_GIVEN_NAME));
        map.put(FAMILY_NAME.name(), Arrays.asList(MOCK_FAMILY_NAME));
        map.put(DATE_OF_BIRTH.name(), Arrays.asList(MOCK_DATE_OF_BIRTH));
        map.put(EMAIL.name(), Arrays.asList(MOCK_EMAIL));
        map.put(EMAIL_VERIFIED.name(), Arrays.asList(false));
        map.put(AMR.name(), Arrays.asList(Arrays.asList(AuthenticationType.IDCard.getAmrName())));
        return map;
    }

    public static HashMap<String, Object> getMockEidasAuthPrincipalAttributes() {
        HashMap<String, Object> map = new HashMap<>();
        map.put(SUB.name(), Arrays.asList(MOCK_SUBJECT_CODE_EIDAS));
        map.put(GIVEN_NAME.name(), Arrays.asList(MOCK_GIVEN_NAME));
        map.put(FAMILY_NAME.name(), Arrays.asList(MOCK_FAMILY_NAME));
        map.put(AMR.name(), Arrays.asList(Arrays.asList(AuthenticationType.eIDAS.getAmrName())));
        map.put(DATE_OF_BIRTH.name(), Arrays.asList(MOCK_DATE_OF_BIRTH));
        map.put(ACR.name(), Arrays.asList(LevelOfAssurance.HIGH.getAcrName()));
        return map;
    }

    public static TicketGrantingTicketImpl getMockUserAuthentication() {
        return getMockUserAuthentication(getMockMidAuthPrincipalAttributes());
    }

    public static TicketGrantingTicketImpl getMockUserAuthentication(Map<String, Object> attributes) {
        Principal taraPrincipal = new DefaultPrincipalFactory().createPrincipal(TARA_PRINCIPAL_ID, attributes);
        DefaultAuthentication userAuthentication = new DefaultAuthentication(ZonedDateTime.of(2018, 1, 1,23,59,00,1, ZoneId.systemDefault()), taraPrincipal, new HashMap<>(), new HashMap<>());
        return new TicketGrantingTicketImpl("123", userAuthentication, Mockito.mock(ExpirationPolicy.class));
    }

    public static DefaultAuthentication getMockBasicAuthentication() {
        Principal principal = new DefaultPrincipalFactory().createPrincipal(MOCK_SUBJECT_CODE_EE);
        HashMap<String, Object> attributes = new HashMap<>();
        attributes.put(OAuth20Constants.STATE, STATE);
        attributes.put(OAuth20Constants.NONCE, NONCE);
        return new DefaultAuthentication(ZonedDateTime.now(ZoneId.systemDefault()), principal, attributes, new HashMap<>());
    }
}
