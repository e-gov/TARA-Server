package ee.ria.sso.service.banklink;

import com.nortal.banklink.authentication.AuthLinkManager;
import com.nortal.banklink.authentication.link.standard.IPizzaStandardAuthLink;
import com.nortal.banklink.core.algorithm.Algorithm008;
import com.nortal.banklink.core.packet.Packet;
import com.nortal.banklink.core.packet.PacketFactory;
import com.nortal.banklink.core.packet.param.PacketParameter;
import com.nortal.banklink.link.BankLinkConfig;
import ee.ria.sso.CommonConstants;
import ee.ria.sso.authentication.BankEnum;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.banklink.BanklinkConfigurationProvider;
import ee.ria.sso.config.banklink.TestBanklinkConfiguration;
import ee.ria.sso.test.SimpleTestAppender;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.test.MockExternalContext;
import org.springframework.webflow.test.MockParameterMap;
import org.springframework.webflow.test.MockRequestContext;

import java.security.KeyPair;
import java.security.PublicKey;
import java.text.MessageFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static ee.ria.sso.config.banklink.BanklinkConfigurationProvider.*;
import static org.hamcrest.Matchers.containsString;


@TestPropertySource(locations= "classpath:application-test.properties")
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestBanklinkConfiguration.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class BanklinkAuthenticationServiceTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    private BanklinkConfigurationProvider banklinkConfigurationProvider;

    @Autowired
    private BanklinkAuthenticationService authenticationService;

    @Autowired
    private Environment environment;

    @Autowired
    private KeyPair rsaKeyPair;

    @Autowired
    private AuthLinkManager authLinkManager;

    @Before
    public void setUp() {
        for ( BankEnum bank : BankEnum.values()) {
            overrideBankKeys(bank, rsaKeyPair);
        }

        SimpleTestAppender.events.clear();
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @After
    public void cleanUp() {
        SimpleTestAppender.events.clear();
    }

    @Test
    public void startLoginByBankLinkFailsWhenNoBankParam() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Requested bank parameter cannot be null nor empty!");

        Map<String, String> map = new HashMap<>();
        Event event = this.authenticationService.startLoginByBankLink(this.getRequestContext(map));
    }

    @Test
    public void startLoginByBankLinkFailsWhenEmptyBankParam() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Requested bank parameter cannot be null nor empty!");

        Map<String, String> map = new HashMap<>();
        map.put("bank", "");

        Event event = this.authenticationService.startLoginByBankLink(this.getRequestContext(map));
    }

    @Test
    public void startLoginByBankLinkFailsWhenIncorrectBankParam() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage(String.format("No enum constant ee.ria.sso.authentication.BankEnum.????",
                Arrays.stream(BankEnum.values()).map(be -> be.getAuthLinkBank().getSpec()).collect(Collectors.toList())
        ));

        Map<String, String> map = new HashMap<>();
        map.put("bank", "????");
        Event event = this.authenticationService.startLoginByBankLink(this.getRequestContext(map));
    }

    @Test
    public void startLoginByBankLinkSucceeds() {
        for (BankEnum bank : BankEnum.values()) {
            verifyStartLoginByBankLinkSucceeds(bank);
        }
    }

    @Test
    public void checkLoginForBankLinkFailsWhenNoInput() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Banklink 1.1.5.1 cause: Unknown banklink message format");

        RequestContext requestContext = this.getRequestContext(new HashMap<>());
        Event event = this.authenticationService.checkLoginForBankLink(requestContext);
    }

    @Test
    public void checkLoginForBankLinkFailsWhenInvalidFormatResponsePacket() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Unknown banklink message format");

        RequestContext requestContext = this.getRequestContext(new HashMap<>());
        MockHttpServletRequest request = (MockHttpServletRequest)requestContext.getExternalContext().getNativeRequest();
        request.addParameter("VK_SOMETHING", "3013");

        Event event = this.authenticationService.checkLoginForBankLink(requestContext);
        Assert.fail("Should not reach this!");
    }


    @Test
    public void checkLoginForBankLinkSucceedsWhenValidResponsePacket() throws Exception {

        RequestContext startLoginRequestCtx = startSuccessfulLoginByBanklink("seb");
        Packet packet = (Packet) startLoginRequestCtx.getRequestScope().get("packet");
        String vkNonce = packet.getParameterValue("VK_NONCE");


        Packet responsePacket = buildResponsePacket(BankEnum.SEB, vkNonce);
        RequestContext callbackRequestCtx = buildMockResponseContext(responsePacket, startLoginRequestCtx);
        addMockNonceToSession(callbackRequestCtx, vkNonce);

        Event event = this.authenticationService.checkLoginForBankLink(callbackRequestCtx);
        verifyCredential(callbackRequestCtx);
        verifySuccessEvent(event);
        SimpleTestAppender.verifyLogEventsExistInOrder(
                containsString(String.format(";openIdDemo;BankLink/%s;START_AUTH;", "SEB")),
                containsString(String.format(";openIdDemo;BankLink/%s;SUCCESSFUL_AUTH;", "SEB"))
        );
    }

    @Test
    public void checkLoginForBankLinkSucceedsWhenValidLhvResponsePacket() throws Exception {
        RequestContext startLoginRequestCtx = startSuccessfulLoginByBanklink(BankEnum.LHV.name().toLowerCase());
        Packet packet = (Packet) startLoginRequestCtx.getRequestScope().get("packet");
        String vkNonce = packet.getParameterValue("VK_NONCE");

        Packet responsePacket = buildResponsePacket(BankEnum.LHV, new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date()), "Leopoldšö Tiiger", vkNonce);
        RequestContext callbackRequestCtx = buildMockResponseContext(responsePacket, startLoginRequestCtx);
        addMockNonceToSession(callbackRequestCtx, vkNonce);

        Event event = this.authenticationService.checkLoginForBankLink(callbackRequestCtx);
        verifyCredential(callbackRequestCtx);
        verifySuccessEvent(event);
    }

    @Test
    public void testGetUnescapedNameFieldWhenCyrillicAlphabetUsed() {
        Assert.assertEquals("БВГДЖЗКЛМНПРСТФХЦЧШЩАЭЫУОЯЕЁЮИЬЪ",
                BanklinkAuthenticationService.getUnescapedNameField("бвгджзклмнпрстфхцчшщаэыуояеёюиьъ")
        );
        Assert.assertEquals("БВГДЖЗКЛМНПРСТФХЦЧШЩАЭЫУОЯЕЁЮИЬЪ",
                BanklinkAuthenticationService.getUnescapedNameField(
                        StringEscapeUtils.escapeHtml4("бвгджзклмнпрстфхцчшщаэыуояеёюиьъ")
                )
        );
    }

    @Test
    public void checkLoginForBankLinkFailsWhenInvalidNonceInResponsePacket() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Invalid banklink message");

        startSuccessfulLoginByBanklink("seb");

        String vkNonce = "invalidNonce....";
        Packet responsePacket = buildResponsePacket(BankEnum.SEB, vkNonce);
        RequestContext callbackRequestCtx = buildMockResponseContext(responsePacket, null);
        addMockNonceToSession(callbackRequestCtx, vkNonce);

        this.authenticationService.checkLoginForBankLink(callbackRequestCtx);
    }

    @Test
    public void checkLoginForBankLinkFailsWhenDateTimeBeforeAllowedLimit() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Invalid banklink message");

        RequestContext startLoginRequestCtx = startSuccessfulLoginByBanklink("seb");
        Packet packet = (Packet) startLoginRequestCtx.getRequestScope().get("packet");
        String vkNonce = packet.getParameterValue("VK_NONCE");

        String vkDateTime = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(
                Date.from(Instant.now().minus(Duration.ofHours(1)))
        );
        Packet responsePacket = buildResponsePacket(BankEnum.SEB, vkDateTime, "TIIGER , LEOPOLD&Scaron;&Ouml;", vkNonce);
        RequestContext callbackRequestCtx = buildMockResponseContext(responsePacket, startLoginRequestCtx);
        addMockNonceToSession(callbackRequestCtx, packet.getParameterValue("VK_NONCE"));

        this.authenticationService.checkLoginForBankLink(callbackRequestCtx);
    }

    @Test
    public void checkLoginForBankLinkFailsWhenDateTimeInTheFuture() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Invalid banklink message");

        RequestContext startLoginRequestCtx = startSuccessfulLoginByBanklink("seb");
        Packet packet = (Packet) startLoginRequestCtx.getRequestScope().get("packet");
        String vkNonce = packet.getParameterValue("VK_NONCE");

        String vkDateTime = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(
                Date.from(Instant.now().plus(Duration.ofMinutes(10)))
        );
        Packet responsePacket = buildResponsePacket(BankEnum.SEB, vkDateTime, "TIIGER , LEOPOLD&Scaron;&Ouml;", vkNonce);
        RequestContext callbackRequestCtx = buildMockResponseContext(responsePacket, startLoginRequestCtx);

        addMockNonceToSession(callbackRequestCtx, packet.getParameterValue("VK_NONCE"));

        this.authenticationService.checkLoginForBankLink(callbackRequestCtx);
    }

    private void verifyCredential(RequestContext callbackRequestCtx) {
        TaraCredential credential = (TaraCredential) callbackRequestCtx.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        Assert.assertNotNull("No credential in session!", credential);

        Assert.assertEquals("Invalid ID in credential!", "EE47302200234", credential.getId());
        Assert.assertEquals("Invalid principal code name in credential!", "EE47302200234", credential.getPrincipalCode());
        Assert.assertEquals("Invalid first name in credential!", "LEOPOLDŠÖ", credential.getFirstName());
        Assert.assertEquals("Invalid last name in credential!", "TIIGER", credential.getLastName());
    }

    private void addMockNonceToSession(RequestContext callbackRequestCtx, String vk_nonce) {
        callbackRequestCtx.getExternalContext().getSessionMap().put(vk_nonce, new Object());
    }

    private void overrideBankKeys(BankEnum bank, KeyPair keyPair) {
        IPizzaStandardAuthLink link = (IPizzaStandardAuthLink)authLinkManager.getBankLink(bank.getAuthLinkBank());
        BankLinkConfig.IPizzaConfig conf = BankLinkConfig.IPizzaConfig.ipizza(
                environment.getProperty(MessageFormat.format(BANK_PARAM_URL, bank.getName())),
                "https://<frontendhost/context>/banklinkAuth",
                environment.getProperty(MessageFormat.format(BANK_PARAM_SENDER_ID, bank.getName())),
                environment.getProperty(MessageFormat.format(BANK_PARAM_RECEIVER_ID, bank.getName())),
                keyPair.getPublic(),
                keyPair.getPrivate());
        link.setConfig(conf);
    }

    private void verifySuccessPacket(BankEnum bank, Packet packet) {
        Assert.assertEquals("Invalid VK_SERVICE!", "4012", packet.getParameterValue("VK_SERVICE"));
        Assert.assertEquals("Invalid VK_VERSION!", "008", packet.getParameterValue("VK_VERSION"));
        Assert.assertEquals("Invalid VK_SND_ID!",
                environment.getProperty(MessageFormat.format(BANK_PARAM_SENDER_ID, bank.getName())),
                packet.getParameterValue("VK_SND_ID")
        );
        Assert.assertEquals("Invalid VK_REC_ID!",
                environment.getProperty(MessageFormat.format(BANK_PARAM_RECEIVER_ID, bank.getName())),
                packet.getParameterValue("VK_REC_ID")
        );
        Assert.assertTrue("Invalid VK_NONCE!",
                Pattern.matches(
                        CommonConstants.UUID_REGEX,
                        packet.getParameterValue("VK_NONCE")
                )
        );
        Assert.assertEquals("Invalid VK_RETURN!",
                banklinkConfigurationProvider.getReturnUrl(),
                packet.getParameterValue("VK_RETURN")
        );

        verifyDateTime(packet.getParameterValue("VK_DATETIME"), Duration.ofHours(1));

        Assert.assertTrue(StringUtils.isEmpty(packet.getParameterValue("VK_RID")));

        verifyMac(packet.getParameterValue("VK_MAC"), packet.parameters(), rsaKeyPair.getPublic());

        Assert.assertEquals("Invalid VK_ENCODING!", "UTF-8", packet.getParameterValue("VK_ENCODING"));
        Assert.assertEquals("Invalid VK_LANG!", "ENG", packet.getParameterValue("VK_LANG"));
    }

    private void verifyUrl(BankEnum bank, RequestContext requestContext) {
        Assert.assertEquals(
                environment.getProperty(MessageFormat.format(BANK_PARAM_URL, bank.getName())),
                requestContext.getRequestScope().get("url")
        );
    }

    private void verifySuccessEvent(Event event) {
        Assert.assertEquals("success", event.getId());
    }

    private void verifyDateTime(String dateTime, TemporalAmount maxAmountInPast) {
        Assert.assertNotNull("DATETIME cannot be missing!", dateTime);

        Instant now = Instant.now();
        Instant instant = null;

        try {
            instant = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").parse(dateTime).toInstant();
        } catch (ParseException e) {
            Assert.fail(String.format("Failed to parse DATETIME (%s): %s", dateTime, e.getMessage()));
        }

        Assert.assertTrue("DATETIME cannot be in the future!",
                instant.compareTo(now) <= 0
        );
        Assert.assertTrue(String.format("DATETIME cannot be older than %s!", now.minus(maxAmountInPast)),
                instant.compareTo(now.minus(maxAmountInPast)) >= 0
        );
    }

    private void verifyMac(String mac, Enumeration<PacketParameter> packetParameters, PublicKey publicKey) {
        Assert.assertNotNull("MAC cannot be missing!", mac);

        Algorithm008 alg = createAlgorithm();
        alg.initVerify(publicKey);

        Assert.assertTrue("Failed to verify MAC!",
                alg.verify(packetParameters, mac)
        );
    }

    private void verifyNonceStoredInSesssion(RequestContext requestContext, Packet packet) {
        Assert.assertNotNull("No session entry was found with key: " + packet.getParameterValue("VK_NONCE") ,requestContext.getExternalContext().getSessionMap().contains(packet.getParameterValue("VK_NONCE")));
    }

    private RequestContext buildMockResponseContext(Packet packet, RequestContext initialRequest) {
        RequestContext requestContext = this.getRequestContext(new HashMap<>());
        MockHttpServletRequest request = (MockHttpServletRequest)requestContext.getExternalContext().getNativeRequest();
        for (PacketParameter param : Collections.list(packet.parameters())) {
            request.addParameter(param.getName(), param.getValue());
        }
        if (initialRequest != null) {
            requestContext.getExternalContext().getSessionMap().putAll(
                    initialRequest.getExternalContext().getSessionMap()
            );
        }
        return requestContext;
    }

    private Packet buildResponsePacket(BankEnum bank, String nonce) {
        String vkDateTime = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date());
        return buildResponsePacket(bank, vkDateTime, "TIIGER , LEOPOLD&Scaron;&Ouml;", nonce);
    }

    private Packet buildResponsePacket(BankEnum bank, String vkDateTime, String vkUserName, String nonce) {
        Algorithm008 alg = createAlgorithm();
        alg.initSign(rsaKeyPair.getPrivate());

        Packet packet = PacketFactory.getPacket(bank.getAuthLinkBank().getSpec(), "3013", alg, null);

        packet.setParameter("VK_SERVICE", "3013");
        packet.setParameter("VK_VERSION", "008");
        packet.setParameter("VK_DATETIME", vkDateTime);
        packet.setParameter("VK_SND_ID", environment.getProperty(MessageFormat.format(BANK_PARAM_RECEIVER_ID, bank.getName())));
        packet.setParameter("VK_REC_ID", environment.getProperty(MessageFormat.format(BANK_PARAM_SENDER_ID, bank.getName())));
        packet.setParameter("VK_NONCE", nonce);
        packet.setParameter("VK_USER_NAME", vkUserName);
        packet.setParameter("VK_USER_ID", "47302200234");
        packet.setParameter("VK_COUNTRY", "EE");
        packet.setParameter("VK_OTHER", "NIMI:TIIGER , LEOPOLD&Scaron;&Ouml;;ISIK:47302200234");
        packet.setParameter("VK_TOKEN", "7");

        packet.setParameter("VK_LANG", "ENG");
        packet.setParameter("VK_RID", "");
        packet.setParameter("VK_ENCODING", "UTF-8");

        String vkMac = alg.sign(packet.parameters());
        packet.setParameter("VK_MAC", vkMac);
        return packet;
    }

    private Algorithm008 createAlgorithm() {
        Algorithm008 alg = new Algorithm008();
        alg.setCharset("UTF-8");
        alg.setLengthInBytes(false);
        return alg;
    }

    private RequestContext startSuccessfulLoginByBanklink(String bank) {
        Locale.setDefault(new Locale("en", "EN"));
        Map<String, String> map = new HashMap<>();
        map.put("bank", bank);
        RequestContext requestContext = this.getRequestContext(map);
        Event event = this.authenticationService.startLoginByBankLink(requestContext);
        verifySuccessEvent(event);
        return requestContext;
    }


    private void verifyStartLoginByBankLinkSucceeds(BankEnum bank) {
        SimpleTestAppender.events.clear();
        Locale.setDefault(new Locale("en", "EN"));
        Map<String, String> map = new HashMap<>();
        map.put("bank", bank.getName());
        RequestContext requestContext = this.getRequestContext(map);

        Event event = this.authenticationService.startLoginByBankLink(requestContext);

        Packet packet = (Packet) requestContext.getRequestScope().get("packet");
        verifySuccessPacket(bank, packet);
        verifyNonceStoredInSesssion(requestContext, packet);
        verifyUrl(bank, requestContext);
        verifySuccessEvent(event);

        SimpleTestAppender.verifyLogEventsExistInOrder(containsString(
                String.format(";openIdDemo;BankLink/%s;START_AUTH;", bank.getName().toUpperCase())
        ));
    }

    private RequestContext getRequestContext(Map<String, String> parameters) {
        MockRequestContext context = new MockRequestContext();

        MockExternalContext mockExternalContext = new MockExternalContext();
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.addParameter("service", "https://cas.test.url.net/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.arendus.kit:8451/oauth/response");
        mockExternalContext.setNativeRequest(mockHttpServletRequest);
        mockExternalContext.setNativeResponse(new MockHttpServletResponse());
        context.setExternalContext(mockExternalContext);

        MockParameterMap map = (MockParameterMap) context.getExternalContext().getRequestParameterMap();
        parameters.forEach((k, v) ->
                map.put(k, v)
        );

        return context;
    }

}
