package ee.ria.sso.config.eidas;

import ee.ria.sso.config.TaraResourceBundleMessageSource;
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
import java.util.*;
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

    @Autowired
    private TaraResourceBundleMessageSource messageSource;

    @NotBlank
    private String serviceUrl;

    private String heartbeatUrl;
    @NotBlank
    private String availableCountries;

    private List<String> listOfCountries;

    private boolean clientCertificateEnabled;

    private String clientCertificateKeystore;

    private String clientCertificateKeystoreType = KeyStore.getDefaultType();

    private String clientCertificateKeystorePass;

    @PostConstruct
    public void init() {
        if (clientCertificateEnabled) {
            Assert.notNull(clientCertificateKeystore, "No client certificate keystore provided");
            Assert.notNull(clientCertificateKeystorePass, "No client certificate keystore password provided");
        }

        listOfCountries = parsePropertiesList(availableCountries);
    }

    private static List<String> parsePropertiesList(String input) {
        if (StringUtils.isEmpty(input)) return Collections.emptyList();
        return Arrays.asList(input.split(","));
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
        return messageSource.getMessage("label.country." + c.toUpperCase(), null, null, locale);
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

}
