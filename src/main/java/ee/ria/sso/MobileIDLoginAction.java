package ee.ria.sso;

import javax.annotation.PostConstruct;

import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import com.codeborne.security.AuthenticationException;
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
	@Qualifier("MIDAuthenticator")
	private MIDAuthenticator mIDAuthenticator;

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
		final String mobileNumber =
				context.getExternalContext().getRequestParameterMap().get("mobileNumber");

		final String personalCode =
				context.getExternalContext().getRequestParameterMap().get("personalCode");

		if (mobileNumber == null || personalCode == null || mobileNumber.trim().length() == 0
				|| personalCode.trim().length() == 0) {
			log.warn(
					"Authentication attemp with empty personalCode or mobileNumber. Forbidden");
			throw new RuntimeException("MID_ERRROR");
		}

		context.getFlowScope().remove("ERROR_CODE");
		log.info("Starting mobile ID login with numbers {} {}", mobileNumber, personalCode);

		try {
			MobileIDSession mIDSession =
					mIDAuthenticator.startLogin(personalCode, countryCode, mobileNumber);
			log.info("Login response: {}", mIDSession);

			context.getFlowScope().put(MOBILE_CHALLENGE, mIDSession.challenge);
			context.getFlowScope().put(MOBILE_NUMBER, mobileNumber);
			context.getFlowScope().put(MOBILE_SESSION, mIDSession);
			context.getFlowScope().put(AUTH_COUNT, 0);

		} catch (AuthenticationException ex) {
			log.error("Mid Login start failed. Msg={}", ex.getMessage());
			clearSession(context);
			throw new RuntimeException("MID_ERRROR");
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
				context.getFlowExecutionContext()
						.getActiveSession()
						.getScope()
						.put("credential", new UsernamePasswordCredential(mobileNumber, session));
				return new Event(this, "success");
			} else {
				context.getFlowScope().put(AUTH_COUNT, ++checkCount);
				return new Event(this, "outstanding");
			}
		} catch (AuthenticationException ex) {
			log.error("Mid Login check failed. Msg={}", ex.getMessage());
			clearSession(context);
			throw new RuntimeException("MID_ERRROR");
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
