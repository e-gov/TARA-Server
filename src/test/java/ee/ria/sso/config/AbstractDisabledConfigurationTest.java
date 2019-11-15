package ee.ria.sso.config;

import org.junit.Assert;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

public abstract class AbstractDisabledConfigurationTest {

    @Autowired
    protected ApplicationContext applicationContext;

    protected void assertBeanNotInitiated(Class clazz) {
        try {
            applicationContext.getBean(clazz);
            Assert.fail("Bean <" + clazz + "> should not be initiated!");
        } catch (NoSuchBeanDefinitionException e) {
        }
    }

    protected void assertBeanNotInitiated(String name) {
        try {
            applicationContext.getBean(name);
            Assert.fail("Bean <" + name + "> should not be initiated!");
        } catch (NoSuchBeanDefinitionException e) {
        }
    }

    protected void assertBeanInitiated(Class clazz) {
        try {
            applicationContext.getBean(clazz);
        } catch (NoSuchBeanDefinitionException e) {
            Assert.fail("Bean <" + clazz + "> is not initiated!");
        }
    }
}
