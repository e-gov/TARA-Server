package ee.ria.sso.config;

import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.LevelOfAssurance;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.env.Environment;

import java.util.Collections;

@RunWith(MockitoJUnitRunner.class)
public class TaraPropertiesTest {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Mock
    Environment env;

    @Test
    public void testInvalidAuthenticationMethodsLoaMapConfiguration() {
        expectedEx.expect(IllegalStateException.class);
        expectedEx.expectMessage("Please check your configuration! Level of assurance (LoA) cannot be " +
                "configured for eIDAS authentication method! NB! The proper LoA for eIDAS authentication is determined " +
                "from the eIDAS authentication response directly.");

        TaraProperties properties = new TaraProperties(env);
        properties.setAuthenticationMethodsLoaMap(Collections.singletonMap(AuthenticationType.eIDAS, LevelOfAssurance.HIGH));
        properties.validateConfiguration();
    }

    @Test
    public void testValidAuthenticationMethodsLoaMapConfiguration() {
        TaraProperties properties = new TaraProperties(env);
        properties.setAuthenticationMethodsLoaMap(Collections.singletonMap(AuthenticationType.IDCard, LevelOfAssurance.HIGH));
        properties.validateConfiguration();
        Assert.assertEquals(LevelOfAssurance.HIGH, properties.getAuthenticationMethodsLoaMap().get(AuthenticationType.IDCard));
    }
}
