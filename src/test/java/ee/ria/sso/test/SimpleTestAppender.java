package ee.ria.sso.test;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.junit.Assert;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertThat;

@Plugin(name = "SimpleTestAppender", category = "Core")
public class SimpleTestAppender extends AbstractAppender {
    public static List<LogEvent> events = new ArrayList<>();

    protected SimpleTestAppender(String name, Filter filter, Layout<? extends Serializable> layout, boolean ignoreExceptions) {
        super(name, filter, layout, ignoreExceptions);
    }

    @Override
    public void append(LogEvent e) {
        events.add(e);
    }

    @PluginFactory
    public static SimpleTestAppender createAppender(
            @PluginAttribute("name") String name,
            @PluginElement("Layout") Layout<? extends Serializable> layout,
            @PluginElement("Filter") final Filter filter,
            @PluginAttribute("otherAttribute") String otherAttribute) {
        if (name == null) {
            LOGGER.error("No name provided for SimpleTestAppender");
            return null;
        }
        if (layout == null) {
            layout = PatternLayout.createDefaultLayout();
        }
        return new SimpleTestAppender(name, filter, layout, true);
    }

    public static void verifyLogEventsExistInOrder(org.hamcrest.Matcher... matchers) {
        Assert.assertTrue("Log events expected, but none found!", CollectionUtils.isNotEmpty(SimpleTestAppender.events));
        List<String> actualItems = SimpleTestAppender.events.stream().map(p -> p.getMessage().getFormattedMessage()).collect(Collectors.toList());
        assertThat(actualItems, IsIterableContainingInOrder.contains(matchers));
    }
}