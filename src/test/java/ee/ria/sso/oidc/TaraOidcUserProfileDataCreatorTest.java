package ee.ria.sso.oidc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;
import org.skyscreamer.jsonassert.comparator.CustomComparator;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Map;

@Slf4j
@RunWith(SpringJUnit4ClassRunner.class)
public class TaraOidcUserProfileDataCreatorTest {

    private static final ObjectWriter WRITER = new ObjectMapper().findAndRegisterModules().writer().withDefaultPrettyPrinter();

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Mock
    AccessToken accessToken;

    @Test
    public void createFromFailsWhenNoTgtPresent() throws Exception {

        Mockito.when(accessToken.getTicketGrantingTicket()).thenReturn(null);

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("TGT cannot be null!");

        Map<String, Object> jsonModel = new TaraOidcUserProfileDataCreator().createFrom(accessToken, null);
    }

    @Test
    public void createFromWithMidPrincipalAttributes() throws Exception {

        mockAttributesInAccessToken(MockPrincipalUtils.getMockMidAuthPrincipalAttributes());

        Map<String, Object> jsonModel = new TaraOidcUserProfileDataCreator().createFrom(accessToken, null);
        verifyJson("{\n" +
                "  \"sub\": \"" + MockPrincipalUtils.MOCK_SUBJECT_CODE_EE + "\",\n" +
                "  \"given_name\": \"" + MockPrincipalUtils.MOCK_GIVEN_NAME + "\",\n" +
                "  \"family_name\": \"" + MockPrincipalUtils.MOCK_FAMILY_NAME + "\",\n" +
                "  \"phone_number\": \"" + MockPrincipalUtils.MOCK_PHONE_NUMBER + "\",\n" +
                "  \"phone_number_verified\": true\n," +
                "  \"date_of_birth\": \"" + MockPrincipalUtils.MOCK_DATE_OF_BIRTH + "\",\n" +
                "  \"amr\": [\n" +
                "    \"" + AuthenticationType.MobileID.getAmrName() + "\"\n" +
                "  ],\n" +
                "  \"auth_time\": 1514843940\n" +
                "}", jsonModel);
    }

    @Test
    public void createFromWithEidasPrincipalAttributes() throws Exception {

        mockAttributesInAccessToken(MockPrincipalUtils.getMockEidasAuthPrincipalAttributes());

        Map<String, Object> jsonModel = new TaraOidcUserProfileDataCreator().createFrom(accessToken, null);
        verifyJson("{\n" +
                "  \"sub\": \"" + MockPrincipalUtils.MOCK_SUBJECT_CODE_EIDAS + "\",\n" +
                "  \"given_name\": \"" + MockPrincipalUtils.MOCK_GIVEN_NAME + "\",\n" +
                "  \"family_name\": \"" + MockPrincipalUtils.MOCK_FAMILY_NAME + "\",\n" +
                "  \"date_of_birth\": \"" + MockPrincipalUtils.MOCK_DATE_OF_BIRTH + "\",\n" +
                "  \"acr\": \"" + LevelOfAssurance.HIGH.getAcrName() + "\",\n" +
                "  \"amr\": [\n" +
                "    \"" + AuthenticationType.eIDAS.getAmrName() + "\"\n" +
                "  ],\n" +
                "  \"auth_time\": 1514843940\n" +
                "}", jsonModel);
    }

    @Test
    public void createFromWithIdCardPrincipalAttributes() throws Exception {

        mockAttributesInAccessToken(MockPrincipalUtils.getMockIdCardAuthPrincipalAttributes());

        Map<String, Object> jsonModel = new TaraOidcUserProfileDataCreator().createFrom(accessToken, null);
        verifyJson("{\n" +
                "  \"sub\": \"" + MockPrincipalUtils.MOCK_SUBJECT_CODE_EE + "\",\n" +
                "  \"given_name\": \"" + MockPrincipalUtils.MOCK_GIVEN_NAME + "\",\n" +
                "  \"family_name\": \"" + MockPrincipalUtils.MOCK_FAMILY_NAME + "\",\n" +
                "  \"date_of_birth\": \"" + MockPrincipalUtils.MOCK_DATE_OF_BIRTH + "\",\n" +
                "  \"email\": \"" + MockPrincipalUtils.MOCK_EMAIL + "\",\n" +
                "  \"email_verified\": false\n," +
                "  \"amr\": [\n" +
                "    \"" + AuthenticationType.IDCard.getAmrName() + "\"\n" +
                "  ],\n" +
                "  \"auth_time\": 1514843940\n" +
                "}", jsonModel);
    }

    private void mockAttributesInAccessToken(Map<String, Object> attributes) {
        Mockito.when(accessToken.getTicketGrantingTicket()).thenReturn(MockPrincipalUtils.getMockUserAuthentication(attributes));
    }

    private void verifyJson(String expectedJson, Map<String, Object> jsonModel) throws JsonProcessingException {
        JSONAssert.assertEquals(
                expectedJson,
                WRITER.writeValueAsString(jsonModel),
                new CustomComparator(JSONCompareMode.NON_EXTENSIBLE)
        );
    }

}
