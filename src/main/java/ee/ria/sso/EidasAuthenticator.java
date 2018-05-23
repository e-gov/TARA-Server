package ee.ria.sso;

import ee.ria.sso.authentication.EidasAuthenticationFailedException;
import ee.ria.sso.authentication.LevelOfAssurance;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

    public byte[] authenticate(String country, String relayState, String loa) throws IOException {
        String uri = eidasClientUrl + "/login" + "?Country=" + country + "&RelayState=" + relayState;
        if (loa != null && Stream.of(LevelOfAssurance.values()).map(LevelOfAssurance::getAcrName)
                .collect(Collectors.toList()).contains(loa)) {
            uri += ("&LoA=" + loa.toUpperCase());
        }

        log.debug("Sending authentication request to eIDAS-Client: <{}>", uri);
        HttpGet get = new HttpGet(uri);
        return httpClient.execute(get, new EidasResponseHandler(), HttpClientContext.create());
    }

    public byte[] getAuthenticationResult(HttpServletRequest request) throws IOException {
        String uri = eidasClientUrl + "/returnUrl";
        log.debug("Requesting authentication result from eIDAS-Client: <{}>", uri);
        HttpPost post = new HttpPost(uri);
        List<NameValuePair> urlParameters = getAuthResultUrlParameters(request);
        post.setEntity(new UrlEncodedFormEntity(urlParameters));
        return httpClient.execute(post, new EidasResponseHandler(), HttpClientContext.create());
    }

    private List<NameValuePair> getAuthResultUrlParameters(HttpServletRequest request) {
        List<NameValuePair> urlParameters = new ArrayList<>();
        Enumeration<String> parameterNames = request.getParameterNames();
        while (parameterNames.hasMoreElements()) {
            String paramName = parameterNames.nextElement();
            String paramValue = request.getParameter(paramName);
            urlParameters.add(new BasicNameValuePair(paramName, paramValue));
        }
        return urlParameters;
    }

    public static class EidasResponseHandler implements ResponseHandler<byte[]> {
        @Override
        public byte[] handleResponse(final HttpResponse response) throws IOException {
            int status = response.getStatusLine().getStatusCode();
            if (status == HttpStatus.SC_OK) {
                HttpEntity entity = response.getEntity();
                return entity != null ? EntityUtils.toByteArray(entity) : null;
            } else if (status == HttpStatus.SC_UNAUTHORIZED) {
                throw new EidasAuthenticationFailedException();
            } else {
                throw new IllegalStateException("eIDAS-Client responded with " + response.getStatusLine().getStatusCode() + " HTTP status code");
            }
        }
    }

    @PreDestroy
    public void cleanUp() throws IOException {
        httpClient.close();
    }
}
