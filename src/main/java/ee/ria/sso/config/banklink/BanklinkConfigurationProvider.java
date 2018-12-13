package ee.ria.sso.config.banklink;

import com.nortal.banklink.authentication.link.standard.IPizzaStandardAuthInfoParser;
import ee.ria.sso.service.banklink.BankEnum;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.validator.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.annotation.PostConstruct;
import java.nio.charset.Charset;
import java.security.*;
import java.text.MessageFormat;
import java.util.*;
import java.util.stream.Collectors;

@Component
@ConditionalOnProperty("banklinks.enabled")
@Configuration
@ConfigurationProperties(prefix = "banklinks")
@Validated
@Getter
@Setter
@Slf4j
public class BanklinkConfigurationProvider {

    public static final int DEFAULT_NONCE_EXPIRATION_TIME_IN_SECONDS = 60 * 60;

    public static final String BANK_PARAM_URL = "banklinks.bank.{0}.url";
    public static final String BANK_PARAM_RECEIVER_ID = "banklinks.bank.{0}.receiver-id";
    public static final String BANK_PARAM_SENDER_ID = "banklinks.bank.{0}.sender-id";
    public static final String BANK_PARAM_PUBLIC_KEY_LABEL = "banklinks.bank.{0}.public-key-alias";
    public static final String BANK_PARAM_PRIVATE_KEY_LABEL = "banklinks.bank.{0}.private-key-alias";
    public static final String BANK_PARAM_PRIVATE_KEY_PASS = "banklinks.bank.{0}.private-key-pass";
    public static final String BANK_PARAM_RESPONSE_PARSER_CLASS = "banklinks.bank.{0}.auth-info-parser-class";
    public static final String BANK_PARAM_NONCE_EXPIRATION_IN_SECONDS = "banklinks.bank.{0}.nonce-expires-in-seconds";
    public static final String BANK_PARAM_TRY_RE_ENCODES = "banklinks.bank.{0}.try-re-encodes";

    @Autowired
    private Environment environment;

    @NotBlank
    private String availableBanks;
    @NotBlank
    private String keystore;

    private String keystoreType = KeyStore.getDefaultType();
    @NotBlank
    private String keystorePass;
    @NotBlank
    private String returnUrl;

    private Map<BankEnum, BankConfiguration> bankConfiguration =  new LinkedHashMap<>();
    private List<BankEnum> listOfBanks;

    @PostConstruct
    public void init() {
        listOfBanks = parseBankList(availableBanks);

        for (BankEnum bank : listOfBanks) {
            bankConfiguration.put(bank, buildBankConfiguration(bank));
        }
    }

    private static List<String> parsePropertiesList(String input) {
        if (input == null || input.isEmpty()) return Collections.emptyList();
        return Arrays.asList(input.split(","));
    }

    private static List<BankEnum> parseBankList(String input) {
        try {
            return parsePropertiesList(input).stream().map( b -> BankEnum.valueOf(b.toUpperCase())).collect(Collectors.toList());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Invalid bank code detected. Allowed values are: " + Arrays.asList(BankEnum.values()).stream().map(b -> b.getName()).collect(Collectors.toList()), e);
        }
    }

    private static List<Charset> parseEncodingList(String input) {
        List<Charset> charsets = parsePropertiesList(input).stream().map( b -> Charset.forName(b)).collect(Collectors.toList());
        return charsets;
    }

    private BankConfiguration buildBankConfiguration(BankEnum bank) {
        String url = environment.getRequiredProperty(MessageFormat.format(BANK_PARAM_URL, bank.getName()));
        String senderId = environment.getRequiredProperty(MessageFormat.format(BANK_PARAM_SENDER_ID, bank.getName()));
        String receiverId = environment.getRequiredProperty(MessageFormat.format(BANK_PARAM_RECEIVER_ID, bank.getName()));
        String publicKeyAlias = environment.getProperty(MessageFormat.format(BANK_PARAM_PUBLIC_KEY_LABEL, bank.getName()), bank.getName());
        String privateKeyAlias = environment.getProperty(MessageFormat.format(BANK_PARAM_PRIVATE_KEY_LABEL, bank.getName()), bank.getName() + "_priv");
        String privateKeyPass = environment.getProperty(MessageFormat.format(BANK_PARAM_PRIVATE_KEY_PASS, bank.getName()), getKeystorePass());
        String responseParserClass = environment.getProperty(MessageFormat.format(BANK_PARAM_RESPONSE_PARSER_CLASS, bank.getName()), IPizzaStandardAuthInfoParser.class.getName());
        Integer nonceExpires = environment.getProperty(MessageFormat.format(BANK_PARAM_NONCE_EXPIRATION_IN_SECONDS, bank.getName()), Integer.class, DEFAULT_NONCE_EXPIRATION_TIME_IN_SECONDS);
        List<Charset> tryReEncodes= parseEncodingList(environment.getProperty(MessageFormat.format(BANK_PARAM_TRY_RE_ENCODES, bank.getName())));

        return new BankConfiguration(
                url, senderId, receiverId,
                nonceExpires,
                publicKeyAlias,
                privateKeyAlias,
                privateKeyPass,
                responseParserClass,
                tryReEncodes
        );
    }

    @Getter
    @RequiredArgsConstructor
    public static class BankConfiguration {
        private final String url;
        private final String senderId;
        private final String receiverId;
        private final int nonceExpirationInSeconds;
        private final String publicKeyAlias;
        private final String privateKeyAlias;
        private final String privateKeyPass;
        private final String responseParserClass;
        private final List<Charset> tryReEncodes;

        @Override
        public String toString() {
            return "BankConfiguration{" +
                    "url='" + url + '\'' +
                    ", senderId='" + senderId + '\'' +
                    ", receiverId='" + receiverId + '\'' +
                    ", publicKeyAlias='" + publicKeyAlias + '\'' +
                    ", privateKeyAlias='" + privateKeyAlias + '\'' +
                    ", nonceExpirationInSeconds=" + nonceExpirationInSeconds +
                    ", privateKeyPass='*******', responseParserClass='" + responseParserClass + '\'' +
                    ", tryReEncodes=" + tryReEncodes +
                    '}';
        }
    }
}
