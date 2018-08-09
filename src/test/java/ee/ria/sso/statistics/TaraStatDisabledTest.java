package ee.ria.sso.statistics;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@TestPropertySource(
        locations= "classpath:application-test.properties",
        properties = { "statistics.tara-stat.enabled=false" })
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
        classes = TestTaraStatHandler.class,
        initializers = ConfigFileApplicationContextInitializer.class)
public class TaraStatDisabledTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    public void whenTaraStatDisabledThenTaraStatBeansNotInitiated() {
        assertBeanNotInitiated(TaraStatHandler.class);
    }

    private void assertBeanNotInitiated(Class clazz) {
        try {
            applicationContext.getBean(clazz);
            Assert.fail("Bean <" + clazz + "> should not be initiated!");
        } catch (NoSuchBeanDefinitionException e) {
            e.printStackTrace();
        }
    }

}
