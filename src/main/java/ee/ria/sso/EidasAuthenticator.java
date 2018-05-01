package ee.ria.sso;

import ee.ria.sso.authentication.EidasAuthenticationFailedException;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

@Component
public class EidasAuthenticator {

    private final Logger log = LoggerFactory.getLogger(EidasAuthenticator.class);

    private CloseableHttpClient httpClient;

    private String eidasClientUrl;

    public EidasAuthenticator() {
        httpClient = HttpClients.createDefault();
    }

    public void setEidasClientUrl(String eidasClientUrl) {
        this.eidasClientUrl = eidasClientUrl;
    }

    public byte[] authenticate(String country, String relayState) throws IOException {
        String uri = eidasClientUrl + "/login" + "?Country=" + country + "&RelayState=" + relayState + "&LoA=LOW";
        log.debug("Sending authentication request to eIDAS-Client: <{}>", uri);
        HttpGet get = new HttpGet(uri);
        HttpResponse response = httpClient.execute(get);
        validateStatusCode(response);
        return IOUtils.toByteArray(response.getEntity().getContent());
    }

    public byte[] getAuthenticationResult(HttpServletRequest request) throws IOException {
        String uri = eidasClientUrl + "/returnUrl";
        log.debug("Requesting authentication result from eIDAS-Client: <{}>", uri);
        HttpPost post = new HttpPost(uri);
        List<NameValuePair> urlParameters = new ArrayList<>();
        Enumeration<String> parameterNames = request.getParameterNames();
        while (parameterNames.hasMoreElements()) {
            String paramName = parameterNames.nextElement();
            String paramValue = request.getParameter(paramName);
            urlParameters.add(new BasicNameValuePair(paramName, paramValue));
        }
        post.setEntity(new UrlEncodedFormEntity(urlParameters));
        HttpResponse response = httpClient.execute(post);
        validateStatusCode(response);
        return IOUtils.toByteArray(response.getEntity().getContent());
    }

    private void validateStatusCode(HttpResponse response) {
        int responseStatusCode = response.getStatusLine().getStatusCode();
        if (responseStatusCode == HttpStatus.SC_OK) {
            return;
        } else if (responseStatusCode == HttpStatus.SC_UNAUTHORIZED) {
            throw new EidasAuthenticationFailedException();
        } else {
            String message = "eIDAS-Client responded with " + response.getStatusLine().getStatusCode() + " HTTP status code";
            log.error(message);
            throw new RuntimeException(message);
        }
    }

}
