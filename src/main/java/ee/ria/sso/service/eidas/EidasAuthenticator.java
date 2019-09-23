package ee.ria.sso.service.eidas;

import ee.ria.sso.authentication.LevelOfAssurance;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import ee.ria.sso.logging.CorrelationIdUtil;
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
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PreDestroy;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class EidasAuthenticator {

    private final Logger log = LoggerFactory.getLogger(EidasAuthenticator.class);

    private final CloseableHttpClient httpClient;

    private final String eidasClientUrl;

    public EidasAuthenticator(EidasConfigurationProvider configurationProvider, CloseableHttpClient httpClient) {
        this.httpClient = httpClient;
        eidasClientUrl = configurationProvider.getServiceUrl();
    }

    public byte[] authenticate(String country, String relayState, LevelOfAssurance loa) throws IOException {
        String uri = eidasClientUrl + "/login" + "?Country=" + country + "&RelayState=" + relayState;
        if (loa != null) uri += ("&LoA=" + loa.getAcrName().toUpperCase());

        log.debug("Sending authentication request to eIDAS-Client: <{}>", uri);

        HttpGet get = new HttpGet(uri);
        CorrelationIdUtil.setCorrelationIdHeadersFromMDC(get);
        return httpClient.execute(get, new EidasResponseHandler(), HttpClientContext.create());
    }

    public byte[] getAuthenticationResult(HttpServletRequest request) throws IOException {
        String uri = eidasClientUrl + "/returnUrl";
        log.debug("Requesting authentication result from eIDAS-Client: <{}>", uri);

        HttpPost post = new HttpPost(uri);
        CorrelationIdUtil.setCorrelationIdHeadersFromMDC(post);
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
                throw new EidasAuthenticationFailedException("eIDAS-Client responded with " + status +" HTTP status code");
            } else {
                throw new IllegalStateException("eIDAS-Client responded with " + status + " HTTP status code");
            }
        }
    }

    @PreDestroy
    public void cleanUp() throws IOException {
        httpClient.close();
    }

}
