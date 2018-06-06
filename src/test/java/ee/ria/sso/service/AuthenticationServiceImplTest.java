package ee.ria.sso.service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.nortal.banklink.authentication.AuthLinkManager;
import com.nortal.banklink.authentication.link.standard.IPizzaStandardAuthLink;
import com.nortal.banklink.core.algorithm.Algorithm008;
import com.nortal.banklink.core.packet.Packet;
import com.nortal.banklink.core.packet.PacketFactory;
import com.nortal.banklink.core.packet.param.PacketParameter;
import com.nortal.banklink.link.BankLinkConfig;
import ee.ria.sso.authentication.BankEnum;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.TaraProperties;
import ee.ria.sso.service.impl.AuthenticationServiceImpl;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;

import ee.ria.sso.AbstractTest;
import org.springframework.webflow.execution.RequestContext;

public class AuthenticationServiceImplTest extends AbstractTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private TaraProperties taraProperties;

    @Autowired
    private KeyPair rsaKeyPair;

    @Autowired
    private AuthLinkManager authLinkManager;

    @Before
    public void setUp() {
        overrideBankKeys(BankEnum.SEB, rsaKeyPair);
    }

    @Test
    public void testStartLoginByMobileIDFailed() {
        expectedEx.expect(RuntimeException.class);

        Map<String, String> map = new HashMap<>();
        map.put("mobileNumber", "+37252839476");
        map.put("principalCode", "38882736672");
        Event event = this.authenticationService.startLoginByMobileID(this.getRequestContext(map));
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
        Locale.setDefault(new Locale("en", "EN"));
        Map<String, String> map = new HashMap<>();
        map.put("bank", "seb");
        RequestContext requestContext = this.getRequestContext(map);

        Event event = this.authenticationService.startLoginByBankLink(requestContext);

        Packet packet = (Packet) requestContext.getRequestScope().get("packet");
        verifySuccessPacket(packet);
        verifyNonceStoredInSesssion(requestContext, packet);
        verifyUrl(requestContext);
        verifySuccessEvent(event);
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
    }


    @Test
    public void checkLoginForBankLinkSucceedsWhenValidResponsePacket() throws Exception {

        RequestContext startLoginRequestCtx = startSuccessfulLoginByBanklink();
        Packet packet = (Packet) startLoginRequestCtx.getRequestScope().get("packet");
        String vkNonce = packet.getParameterValue("VK_NONCE");


        Packet responsePacket = buildResponsePacket(rsaKeyPair.getPrivate(), vkNonce);
        RequestContext callbackRequestCtx = buildMockResponseContext(responsePacket);
        addMockNonceToSession(callbackRequestCtx, vkNonce);

        Event event = this.authenticationService.checkLoginForBankLink(callbackRequestCtx);
        verifyCredential(callbackRequestCtx);
        verifySuccessEvent(event);
    }

    @Test
    public void testGetUnescapedNameFieldWhenCyrillicAlphabetUsed() {
        Assert.assertEquals("БВГДЖЗКЛМНПРСТФХЦЧШЩАЭЫУОЯЕЁЮИЬЪ",
                AuthenticationServiceImpl.getUnescapedNameField("бвгджзклмнпрстфхцчшщаэыуояеёюиьъ")
        );
        Assert.assertEquals("БВГДЖЗКЛМНПРСТФХЦЧШЩАЭЫУОЯЕЁЮИЬЪ",
                AuthenticationServiceImpl.getUnescapedNameField(
                        StringEscapeUtils.escapeHtml4("бвгджзклмнпрстфхцчшщаэыуояеёюиьъ")
                )
        );
    }

    private void verifyCredential(RequestContext callbackRequestCtx) {
        TaraCredential credential = (TaraCredential) callbackRequestCtx.getFlowExecutionContext().getActiveSession().getScope().get("credential");
        Assert.assertNotNull("No credential in session!", credential);

        Assert.assertEquals("Invalid ID in credential!", "EE47302200234", credential.getId());
        Assert.assertEquals("Invalid principal code name in credential!", "EE47302200234", credential.getPrincipalCode());
        Assert.assertEquals("Invalid first name in credential!", "LEOPOLDŠÖ", credential.getFirstName());
        Assert.assertEquals("Invalid last name in credential!", "TIIGER", credential.getLastName());
    }


    @Test
    public void checkLoginForBankLinkFailsWhenInvalidNonceInResponsePacket() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Invalid banklink message");

        startSuccessfulLoginByBanklink();

        String vkNonce = "invalidNonce....";
        Packet responsePacket = buildResponsePacket(rsaKeyPair.getPrivate(), vkNonce);
        RequestContext callbackRequestCtx = buildMockResponseContext(responsePacket);
        addMockNonceToSession(callbackRequestCtx, vkNonce);

        this.authenticationService.checkLoginForBankLink(callbackRequestCtx);
    }

    @Test
    public void checkLoginForBankLinkFailsWhenDateTimeBeforeAllowedLimit() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Invalid banklink message");

        RequestContext startLoginRequestCtx = startSuccessfulLoginByBanklink();
        Packet packet = (Packet) startLoginRequestCtx.getRequestScope().get("packet");
        String vkNonce = packet.getParameterValue("VK_NONCE");

        String vkDateTime = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(
                Date.from(Instant.now().minus(Duration.ofHours(1)))
        );
        Packet responsePacket = buildResponsePacket(rsaKeyPair.getPrivate(), vkNonce, vkDateTime);
        RequestContext callbackRequestCtx = buildMockResponseContext(responsePacket);
        addMockNonceToSession(callbackRequestCtx, packet.getParameterValue("VK_NONCE"));

        this.authenticationService.checkLoginForBankLink(callbackRequestCtx);
    }

    @Test
    public void checkLoginForBankLinkFailsWhenDateTimeInTheFuture() {
        expectedEx.expect(TaraAuthenticationException.class);
        expectedEx.expectMessage("Invalid banklink message");

        RequestContext startLoginRequestCtx = startSuccessfulLoginByBanklink();
        Packet packet = (Packet) startLoginRequestCtx.getRequestScope().get("packet");
        String vkNonce = packet.getParameterValue("VK_NONCE");

        String vkDateTime = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(
                Date.from(Instant.now().plus(Duration.ofMinutes(10)))
        );
        Packet responsePacket = buildResponsePacket(rsaKeyPair.getPrivate(), vkNonce, vkDateTime);
        RequestContext callbackRequestCtx = buildMockResponseContext(responsePacket);

        addMockNonceToSession(callbackRequestCtx, packet.getParameterValue("VK_NONCE"));

        this.authenticationService.checkLoginForBankLink(callbackRequestCtx);
    }

    private void addMockNonceToSession(RequestContext callbackRequestCtx, String vk_nonce) {
        callbackRequestCtx.getExternalContext().getSessionMap().put(vk_nonce, new Object());
    }

    @Test
    public void checkLoginForBankLinkFailsWhenNoSessionIsFound() {
        RequestContext startLoginRequestCtx = startSuccessfulLoginByBanklink();
        Packet packet = (Packet) startLoginRequestCtx.getRequestScope().get("packet");
        String vkNonce = packet.getParameterValue("VK_NONCE");

        expectedEx.expect(RuntimeException.class);
        expectedEx.expectMessage(
                "Bank response's nonce " + vkNonce + " not found among previously stored nonces!"
        );

        Packet responsePacket = buildResponsePacket(rsaKeyPair.getPrivate(), vkNonce);
        RequestContext callbackRequestCtx = buildMockResponseContext(responsePacket);

        this.authenticationService.checkLoginForBankLink(callbackRequestCtx);
    }

    private void overrideBankKeys(BankEnum bank, KeyPair keyPair) {
        IPizzaStandardAuthLink link = (IPizzaStandardAuthLink)authLinkManager.getBankLink(bank.getAuthLinkBank());
        BankLinkConfig.IPizzaConfig conf = BankLinkConfig.IPizzaConfig.ipizza(
                taraProperties.getEnvironment().getProperty(bank.getUrlCode()),
                "https://<frontendhost/context>/banklinkAuth",
                taraProperties.getEnvironment().getProperty(bank.getVkSenderIdCode()),
                taraProperties.getEnvironment().getProperty(bank.getVkRecIdCode()),
                keyPair.getPublic(),
                keyPair.getPrivate());
        link.setConfig(conf);
    }

    private void verifySuccessPacket(Packet packet) {

        Assert.assertEquals("Invalid VK_SERVICE!", "4012", packet.getParameterValue("VK_SERVICE"));
        Assert.assertEquals("Invalid VK_VERSION!", "008", packet.getParameterValue("VK_VERSION"));
        Assert.assertEquals("Invalid VK_SND_ID!",
                taraProperties.getEnvironment().getProperty("bank.seb.sender.id"),
                packet.getParameterValue("VK_SND_ID")
        );
        Assert.assertEquals("Invalid VK_REC_ID!",
                taraProperties.getEnvironment().getProperty("bank.seb.rec.id"),
                packet.getParameterValue("VK_REC_ID")
        );
        Assert.assertTrue("Invalid VK_NONCE!",
                Pattern.matches(
                        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
                        packet.getParameterValue("VK_NONCE")
                )
        );
        Assert.assertEquals("Invalid VK_RETURN!",
                taraProperties.getEnvironment().getProperty("bank.returnUrl"),
                packet.getParameterValue("VK_RETURN")
        );

        verifyDateTime(packet.getParameterValue("VK_DATETIME"), Duration.ofHours(1));

        Assert.assertTrue(StringUtils.isEmpty(packet.getParameterValue("VK_RID")));

        verifyMac(packet.getParameterValue("VK_MAC"), packet.parameters(), rsaKeyPair.getPublic());

        Assert.assertEquals("Invalid VK_ENCODING!", "UTF-8", packet.getParameterValue("VK_ENCODING"));
        Assert.assertEquals("Invalid VK_LANG!", "ENG", packet.getParameterValue("VK_LANG"));
    }

    private void verifyUrl(RequestContext requestContext) {
        Assert.assertEquals(
                taraProperties.getEnvironment().getProperty("bank.seb.url"),
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

    private RequestContext buildMockResponseContext(Packet packet) {
        RequestContext requestContext = this.getRequestContext(new HashMap<>());
        MockHttpServletRequest request = (MockHttpServletRequest)requestContext.getExternalContext().getNativeRequest();
        for (PacketParameter param : Collections.list(packet.parameters())) {
            request.addParameter(param.getName(), param.getValue());
        }
        return requestContext;
    }

    private Packet buildResponsePacket(PrivateKey privateKey, String nonce) {
        String vkDateTime = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(new Date());
        return buildResponsePacket(privateKey, nonce, vkDateTime);
    }

    private Packet buildResponsePacket(PrivateKey privateKey, String nonce, String vkDateTime) {
        Algorithm008 alg = createAlgorithm();
        alg.initSign(privateKey);

        Packet packet = PacketFactory.getPacket(BankEnum.SEB.getAuthLinkBank().getSpec(), "3013", alg, null);

        packet.setParameter("VK_SERVICE", "3013");
        packet.setParameter("VK_VERSION", "008");
        packet.setParameter("VK_DATETIME", vkDateTime);
        packet.setParameter("VK_SND_ID", "EYP");
        packet.setParameter("VK_REC_ID", "testvpos");
        packet.setParameter("VK_NONCE", nonce);
        packet.setParameter("VK_USER_NAME", "TIIGER , LEOPOLD&Scaron;&Ouml;");
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

    private RequestContext startSuccessfulLoginByBanklink() {
        Locale.setDefault(new Locale("en", "EN"));
        Map<String, String> map = new HashMap<>();
        map.put("bank", "seb");
        RequestContext requestContext = this.getRequestContext(map);
        Event event = this.authenticationService.startLoginByBankLink(requestContext);
        verifySuccessEvent(event);
        return requestContext;
    }

}
