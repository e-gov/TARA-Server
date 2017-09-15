package ee.ria.sso;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;

import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.webflow.core.collection.AttributeMap;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.mobileid.MobileIDAuthenticator;
import com.codeborne.security.mobileid.MobileIDSession;

/**
 * Created by serkp on 7.09.2017.
 */
@Component("mobileIDLoginAction")
public class MobileIDLoginAction {

	private static final Logger log = LoggerFactory.getLogger(MobileIDLoginAction.class);

	public static final String MOBILE_CHALLENGE = "mobileChallenge";
	public static final String MOBILE_SESSION = "mobileSession";
	public static final String MOBILE_NUMBER = "mobileNumber";
	public static final String AUTH_COUNT = "authCount";

	@Autowired
	@Qualifier("mobileIDAuthenticator")
	private MobileIDAuthenticator mIDAuthenticator;

	@Value("${mobileID.countryCode:EE}")
	private String countryCode;

	@Value("${mobileID.language:EST}")
	private String language;

	@Value("${mobileID.serviceName:Testimine}")
	private String serviceName;

	@Value("${mobileID.messageToDisplay:''}")
	private String messageToDisplay;

	@Value("${mobileID.serviceUrl:https://tsp.demo.sk.ee}")
	private String serviceUrl;

	public Event submit(RequestContext context) {
		String mobileNumber =
				context.getExternalContext().getRequestParameterMap().get("mobileNumber");

		context.getFlowScope().remove("ERROR_CODE");
		log.info("Starting mobile ID login with number {}", mobileNumber);

		try {
			MobileIDSession mIDSession = mIDAuthenticator.startLogin(mobileNumber);
			log.info("Login response: {}", mIDSession);

			context.getFlowScope().put(MOBILE_CHALLENGE, mIDSession.challenge);
			context.getFlowScope().put(MOBILE_NUMBER, mobileNumber);
			context.getFlowScope().put(MOBILE_SESSION, mIDSession);
			context.getFlowScope().put(AUTH_COUNT, 0);

		} catch (AuthenticationException ex) {
			log.error("Mid Login start failed. Msg={}", ex.getMessage());
			clearSession(context);
			context.getFlowScope().put("ERROR_CODE", "mid." + ex.getCode());

			return new Event(this, "error");
		}

		return new Event(this, "success");
	}

	public Event check(RequestContext context) {
		MobileIDSession session = (MobileIDSession) context.getFlowScope().get(MOBILE_SESSION);
		int checkCount = (int) context.getFlowScope().get(AUTH_COUNT);
		String mobileNumber = (String) context.getFlowScope().get(MOBILE_NUMBER);

		log.debug("Checking (attempt {}) mobile ID login state with session code {}", checkCount,
				session.sessCode);

		try {
			boolean isLoginComplete = mIDAuthenticator.isLoginComplete(session);

			if (isLoginComplete) {

				Map<String, String> map = new HashMap<String, String>();
				map.put("testAttribute", "test");
				AttributeMap attributeMap = new LocalAttributeMap(map);
				context.getFlowExecutionContext()
						.getActiveSession()
						.getScope()
						.put("credential", new UsernamePasswordCredential(mobileNumber, session));
				//context.getFlowScope().put("credential", new UsernamePasswordCredential(mobileNumber, session));
				return new Event(this, "success", attributeMap);
			} else {
				context.getFlowScope().put(AUTH_COUNT, ++checkCount);
				return new Event(this, "outstanding");
			}
		} catch (AuthenticationException ex) {
			log.error("Mid Login check failed. Msg={}", ex.getMessage());
			clearSession(context);
			context.getFlowScope().put("ERROR_CODE", "mid." + ex.getCode());
			return new Event(this, "error");
		}
	}

	@PostConstruct
	public void init() {
		mIDAuthenticator.setDigidocServiceURL(serviceUrl);
		mIDAuthenticator.setLanguage(language);
		mIDAuthenticator.setLoginMessage(messageToDisplay);
		mIDAuthenticator.setServiceName(serviceName);
	}

	private void clearSession(RequestContext context) {
		context.getFlowScope().remove(MOBILE_CHALLENGE);
		context.getFlowScope().remove(UsernamePasswordCredential.class.getSimpleName());
		context.getFlowScope().remove(MOBILE_NUMBER);
		context.getFlowScope().remove(MOBILE_SESSION);
		context.getFlowScope().remove(AUTH_COUNT);
	}
}
