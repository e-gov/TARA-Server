package ee.ria.sso.service.idcard;

import ee.ria.sso.config.idcard.IDCardConfigurationProvider;
import ee.ria.sso.utils.X509Utils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.util.Assert;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class OCSPConfigurationResolver {

    private final IDCardConfigurationProvider configurationProvider;

    public List<IDCardConfigurationProvider.Ocsp> resolve(X509Certificate userCert) {
        log.debug("Determining the OCSP configuration");
        Assert.notNull(userCert, "User certificate is missing!");
        final List<IDCardConfigurationProvider.Ocsp> ocspConfiguration = new ArrayList<>();

        String issuerCN = X509Utils.getIssuerCNFromCertificate(userCert);

        IDCardConfigurationProvider.Ocsp primaryConf = getOcspConfiguration(issuerCN, configurationProvider.getOcsp())
                .orElse(getDefaultConf(userCert, issuerCN));
        log.debug("Primary ocsp configuration to verify cert issued by '{}': {}", issuerCN, primaryConf);
        ocspConfiguration.add(primaryConf);

        if (CollectionUtils.isNotEmpty(configurationProvider.getFallbackOcsp())) {
            List<IDCardConfigurationProvider.Ocsp> secondaryConfs = configurationProvider.getFallbackOcsp().stream().filter(
                    e -> e.getIssuerCn().stream().anyMatch( b -> b.equals(issuerCN))
            ).collect(Collectors.toList());
            log.debug("Secondary ocsp configurations to verify cert issued by '{}': {}", issuerCN, secondaryConfs);
            ocspConfiguration.addAll(secondaryConfs);
        }

        log.debug("OCSP configurations: {}", ocspConfiguration);
        return ocspConfiguration;
    }

    private IDCardConfigurationProvider.Ocsp getDefaultConf(X509Certificate userCert, String issuerCN) {
        String url = X509Utils.getOCSPUrl(userCert);
        Assert.notNull(url, "OCSP configuration invalid! This user certificate's issuer, issued by '" + issuerCN +
                "', has no explicitly configured OCSP nor can it be configured automatically since this certificate does not contain " +
                "the OCSP url in the AIA extension! Please check your configuration");
        IDCardConfigurationProvider.Ocsp implicitConfiguration = new IDCardConfigurationProvider.Ocsp();
        implicitConfiguration.setIssuerCn(Arrays.asList(issuerCN));
        implicitConfiguration.setUrl(url);
        log.debug("Did not find explicit config for issuer '{}' - using default configuration with AIA extension url: {} to verify cert status", issuerCN, url);
        return implicitConfiguration;
    }

    private Optional<IDCardConfigurationProvider.Ocsp> getOcspConfiguration(String issuerCN, List<IDCardConfigurationProvider.Ocsp> configurations) {
        return configurations.stream().filter(
                e -> e.getIssuerCn().stream().anyMatch( b -> b.equals(issuerCN))
        ).findFirst();
    }
}
