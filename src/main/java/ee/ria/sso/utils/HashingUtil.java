package ee.ria.sso.utils;

import java.nio.charset.StandardCharsets;

import org.apereo.cas.util.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import ee.ria.sso.config.TaraProperties;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Component
public class HashingUtil {

    private static TaraProperties taraProperties;

    public static String hash(String secret) {
        return DigestUtils.digest(HashingUtil.taraProperties.getApplication().getDigestAlgorithm(),
            secret.getBytes(StandardCharsets.UTF_8));
    }

    /*
     * ACCESSORS
     */

    @Autowired
    public void setTaraProperties(TaraProperties taraProperties) {
        HashingUtil.taraProperties = taraProperties;
    }

}
