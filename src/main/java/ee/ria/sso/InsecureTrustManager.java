package ee.ria.sso;

import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public class InsecureTrustManager implements X509TrustManager {

    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    public void checkClientTrusted(X509Certificate[] certs, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] certs, String authType) {
    }

}