package ee.ria.sso.service;

import java.security.KeyPair;
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
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
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

    @Test
    public void testStartLoginByMobileIDFailed() {
        expectedEx.expect(RuntimeException.class);

        Map<String, String> map = new HashMap<>();
        map.put("mobileNumber", "+37252839476");
        map.put("principalCode", "38882736672");
        Event event = this.authenticationService.startLoginByMobileID(this.getRequestContext(map));
    }
}
