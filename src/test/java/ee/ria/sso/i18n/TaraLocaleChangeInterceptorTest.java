package ee.ria.sso.i18n;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.LocaleResolver;
import java.util.Locale;

@RunWith(SpringJUnit4ClassRunner.class)
public class TaraLocaleChangeInterceptorTest {

    @Mock
    LocaleResolver localeResolver;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    MockHttpServletRequest servletRequest;

    MockHttpServletResponse servletResponse;

    TaraLocaleChangeInterceptor interceptor;

    @Before
    public void setUp() throws Exception {
        servletRequest = new MockHttpServletRequest();
        servletResponse = new MockHttpServletResponse();
        servletRequest.setAttribute(DispatcherServlet.LOCALE_RESOLVER_ATTRIBUTE, localeResolver);
        interceptor = new TaraLocaleChangeInterceptor();
    }

    @Test
    public void noParametersInRequest() throws Exception {
        interceptor.preHandle(servletRequest, servletResponse, null);
        Mockito.verify(localeResolver, Mockito.never()).setLocale(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    public void noLocaleResolverFoundInRequest() throws Exception {
        expectedEx.expect(IllegalStateException.class);
        expectedEx.expectMessage("No LocaleResolver found: not in a DispatcherServlet request?");

        servletRequest.addParameter("ui_locales", "en");
        servletRequest.setAttribute(DispatcherServlet.LOCALE_RESOLVER_ATTRIBUTE, null);
        interceptor.preHandle(servletRequest, servletResponse, null);

        Mockito.verify(localeResolver, Mockito.never()).setLocale(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    public void validDefaultLocaleParameterWithValidValueInRequestUpdatesLocale() throws Exception {
        servletRequest.addParameter(TaraLocaleChangeInterceptor.DEFAULT_OIDC_LOCALE_PARAM, "en");

        interceptor.preHandle(servletRequest, servletResponse, null);
        Mockito.verify(localeResolver).setLocale(Mockito.eq(servletRequest), Mockito.eq(servletResponse), Mockito.eq(Locale.forLanguageTag("en")));
    }

    @Test
    public void multipleValidLocaleParametersWithValidValuesFirstParameterIsUsedToUpdateLocale() throws Exception {
        interceptor.setParamNames(new String[] {"ui_locales", "locale"});

        servletRequest.addParameter("ui_locales", "ru");
        servletRequest.addParameter("locale", "et");
        servletRequest.addParameter("lang", "en");

        interceptor.preHandle(servletRequest, servletResponse, null);
        Mockito.verify(localeResolver).setLocale(Mockito.eq(servletRequest), Mockito.eq(servletResponse), Mockito.eq(Locale.forLanguageTag("ru")));
    }

    @Test
    public void invalidLocaleParameterWithValidValueInRequestIsIgnored() throws Exception {
        servletRequest.addParameter("invalid_ui_locale_param", "en");

        interceptor.preHandle(servletRequest, servletResponse, null);
        Mockito.verify(localeResolver, Mockito.never()).setLocale(Mockito.eq(servletRequest), Mockito.eq(servletResponse), Mockito.eq(Locale.forLanguageTag("en")));
    }

    @Test
    public void validLocaleParameterWithInvalidValueInRequestThrowsException() throws Exception {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Invalid value specified for language selection. Supported values are: [et, en, ru]");
        servletRequest.addParameter("ui_locales", "xxxxxxxx");

        interceptor.preHandle(servletRequest, servletResponse, null);
        Mockito.verify(localeResolver, Mockito.never()).setLocale(Mockito.eq(servletRequest), Mockito.eq(servletResponse), Mockito.any());
    }

    @Test
    public void validLocaleParameterWithInvalidValueInRequestIsIgnored() throws Exception {
        servletRequest.addParameter("ui_locales", "xxxxxxxx");

        interceptor.setIgnoreInvalidLocale(true);
        interceptor.preHandle(servletRequest, servletResponse, null);
        Mockito.verify(localeResolver, Mockito.never()).setLocale(Mockito.eq(servletRequest), Mockito.eq(servletResponse), Mockito.any());
    }
}
