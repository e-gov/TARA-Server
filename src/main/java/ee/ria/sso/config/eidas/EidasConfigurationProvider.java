package ee.ria.sso.config.eidas;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.oidc.TaraScopeValuedAttributeName;
import ee.ria.sso.utils.CountryCodeUtil;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.validator.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import javax.annotation.PostConstruct;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
@ConditionalOnProperty("eidas.enabled")
@Configuration
@ConfigurationProperties(prefix = "eidas")
@Validated
@Getter
@Setter
@Slf4j
public class EidasConfigurationProvider {

    private static final int CONNECTION_POOL_DEFAULT_MAX_TOTAL = 20;
    private static final int CONNECTION_POOL_DEFAULT_MAX_PER_ROUTE = 2;

    @Autowired
    private TaraResourceBundleMessageSource messageSource;

    @NotBlank
    private String serviceUrl;

    private String heartbeatUrl;
    @NotBlank
    private String availableCountries;

    private List<String> listOfCountries;

    private List<String> allowedEidasCountryScopeAttributes;

    private boolean clientCertificateEnabled;

    private String clientCertificateKeystore;

    private String clientCertificateKeystoreType = KeyStore.getDefaultType();

    private String clientCertificateKeystorePass;

    private ConnectionPool connectionPool = new ConnectionPool();

    @PostConstruct
    public void init() {
        if (clientCertificateEnabled) {
            Assert.notNull(clientCertificateKeystore, "No client certificate keystore provided");
            Assert.notNull(clientCertificateKeystorePass, "No client certificate keystore password provided");
        }

        listOfCountries = parseAvailableCountries(availableCountries);
        allowedEidasCountryScopeAttributes = constructEidasCountryScopeAttributes(listOfCountries);
    }

    private static List<String> parseAvailableCountries(String input) {
        if (StringUtils.isBlank(input)) {
            return Collections.emptyList();
        }
        List<String> countryCodes = Arrays.asList(input.split(","));
        validateCountryCodes(countryCodes);
        return countryCodes;
    }

    private List<String> constructEidasCountryScopeAttributes(List<String> allowedCountryCodes) {
        return allowedCountryCodes.stream()
                .map(countryCode -> TaraScopeValuedAttributeName.EIDAS_COUNTRY.getFormalName() + ":" + countryCode.toLowerCase())
                .collect(Collectors.toList());
    }

    private static void validateCountryCodes(List<String> countryCodes) {
        for (String countryCode : countryCodes) {
            Assert.isTrue(CountryCodeUtil.isValidCountryCode(countryCode), "Invalid ISO 3166-1 alpha-2 country code '" + countryCode + "'");
        }
    }

    public List<String> getListOfCountries(String locale) {
        try {
            return getSortedByLocaleNameList(locale == null ? LocaleContextHolder.getLocale() : new Locale(locale));
        } catch (Exception e) {
            log.error("Failed to compile the list of countries for the specified locale!", e);
        }

        return Collections.emptyList();
    }

    private List<String> getSortedByLocaleNameList(Locale locale) {
        return listOfCountries.stream()
                .map(c -> new Country(c, getCountryTranslation(locale, c)))
                .sorted()
                .map(Country::getCode)
                .collect(Collectors.toList());
    }

    private String getCountryTranslation(Locale locale, String c) {
        return messageSource.getMessage("label.countries." + c.toUpperCase(), null, null, locale);
    }

    public class Country implements Comparable<Country> {

        private final String code;
        private final String name;

        public Country(String code, String name) {
            this.code = code;
            this.name = name;
        }

        public String getCode() {
            return code;
        }

        public String getName() {
            return name;
        }

        @Override
        public int compareTo(Country o) {
            return this.getName().compareTo(o.getName());
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Country)) return false;
            Country country = (Country) o;
            return Objects.equals(code, country.code) &&
                    Objects.equals(name, country.name);
        }

        @Override
        public int hashCode() {
            return Objects.hash(code, name);
        }
    }

    @Getter
    @Setter
    public static class ConnectionPool {
        private int maxTotal = CONNECTION_POOL_DEFAULT_MAX_TOTAL;
        private int maxPerRoute = CONNECTION_POOL_DEFAULT_MAX_PER_ROUTE;
    }

}
