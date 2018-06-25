package ee.ria.sso.config;

import ee.ria.sso.AbstractTest;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class TaraPropertiesTest extends AbstractTest {

    @Autowired
    private TaraProperties taraProperties;

    @Test
    public void testApplicationVersion() {
        Assert.assertNotEquals("Is not different", "-", this.taraProperties.getApplicationVersion());
    }

}
