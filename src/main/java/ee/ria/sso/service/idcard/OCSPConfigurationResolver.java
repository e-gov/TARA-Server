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

@Slf4j
@RequiredArgsConstructor
public class OCSPConfigurationResolver {

    private final IDCardConfigurationProvider configurationProvider;

    public List<IDCardConfigurationProvider.Ocsp> resolve(X509Certificate userCert) {
        log.debug("Determining the OCSP configuration");
        Assert.notNull(userCert, "User certificate is missing!");
        final List<IDCardConfigurationProvider.Ocsp> ocspConfiguration = new ArrayList<>();

        String issuerCN = X509Utils.getIssuerCNFromCertificate(userCert);

        Optional<IDCardConfigurationProvider.Ocsp> explicitConf = getOcspConfiguration(issuerCN);
        if (!explicitConf.isPresent()) {
            String url = X509Utils.getOCSPUrl(userCert);
            Assert.notNull(url, "OCSP configuration invalid! This user certificate's issuer, issued by '" + issuerCN +
                    "', has no explicitly configured OCSP nor can it be configured automatically since this certificate does not contain " +
                    "the OCSP url in the AIA extension! Please check your configuration");
            IDCardConfigurationProvider.Ocsp implicitConfiguration = new IDCardConfigurationProvider.Ocsp();
            implicitConfiguration.setIssuerCn(Arrays.asList(issuerCN));
            implicitConfiguration.setUrl(url);
            ocspConfiguration.add(implicitConfiguration);

            log.debug("Using AIA extension and default configuration to to verify cert issed by '{}'", issuerCN);
        } else {
            log.debug("Using explicit configuration to verify cert issued by '{}'", issuerCN, explicitConf.get());
            ocspConfiguration.add(explicitConf.get());
        }

        if (CollectionUtils.isNotEmpty(configurationProvider.getFallbackOcsp())) {
            ocspConfiguration.addAll(configurationProvider.getFallbackOcsp());
            log.debug("Added {} secondary fallback ocsp configurations", configurationProvider.getFallbackOcsp().size());
        }

        log.debug("OCSP configuration: {}", ocspConfiguration);
        return ocspConfiguration;
    }

    private Optional<IDCardConfigurationProvider.Ocsp> getOcspConfiguration(String issuerCN) {
        return configurationProvider.getOcsp().stream().filter(
                e -> e.getIssuerCn().stream().anyMatch( b -> b.equals(issuerCN))
        ).findFirst();
    }
}
