package ee.ria.sso.service.banklink;

import com.nortal.banklink.authentication.AuthLink;
import com.nortal.banklink.authentication.AuthLinkInfo;
import com.nortal.banklink.authentication.AuthLinkManager;
import com.nortal.banklink.core.packet.Packet;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.security.CspDirective;
import ee.ria.sso.security.CspHeaderUtil;
import ee.ria.sso.service.AbstractService;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import ee.ria.sso.statistics.StatisticsRecord;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.inspektr.audit.annotation.Audit;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;

import static ee.ria.sso.Constants.CAS_SERVICE_ATTRIBUTE_NAME;

@ConditionalOnProperty("banklinks.enabled")
@Service
@Slf4j
public class BanklinkAuthenticationService extends AbstractService {

    private static final String BANK_ENUM_ATTRIBUTE = "banklinkBankEnum";

    private final AuthLinkManager authLinkManager;

    public BanklinkAuthenticationService(TaraResourceBundleMessageSource messageSource, StatisticsHandler statistics, AuthLinkManager authLinkManager) {
        super(statistics, messageSource);
        this.authLinkManager = authLinkManager;
    }

    @Audit(
            action = "BANKLINK_AUTHENTICATION_INIT",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event startLoginByBankLink(RequestContext context) {
        try {
            String bankCode = context.getRequestParameters().get("bank");
            if (StringUtils.isEmpty(bankCode)) {
                throw new IllegalStateException("Requested bank parameter cannot be null nor empty!");
            }

            BankEnum bankEnum = BankEnum.valueOf(bankCode.toUpperCase());
            context.getExternalContext().getSessionMap().put(BANK_ENUM_ATTRIBUTE, bankEnum);

            AuthLink banklink = authLinkManager.getBankLink(bankEnum.getAuthLinkBank());
            context.getRequestScope().put("url", banklink.getUrl());

            Packet outgoingPacket = banklink.createOutgoingPacket();
            outgoingPacket.setParameter("VK_LANG", LocaleContextHolder.getLocale().getISO3Language().toUpperCase());
            context.getRequestScope().put("packet", outgoingPacket);
            context.getExternalContext().getSessionMap().put(CAS_SERVICE_ATTRIBUTE_NAME, context.getFlowScope().get(CAS_SERVICE_ATTRIBUTE_NAME));
            addBankUrlToResponseCspFormActionDirective(context, banklink);

            logEvent(new StatisticsRecord(LocalDateTime.now(), getServiceClientId(context), bankEnum, StatisticsOperation.START_AUTH));

            return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
        } catch (Exception e) {
            logFailureEvent(context, e);
            throw e;
        }
    }

    @Audit(
            action = "BANKLINK_AUTHENTICATION_CALLBACK",
            actionResolverName = "AUTHENTICATION_RESOLVER",
            resourceResolverName = "TARA_AUTHENTICATION_RESOURCE_RESOLVER"
    )
    public Event checkLoginForBankLink(RequestContext context) {
        try {
            HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getNativeRequest();
            context.getFlowScope().put(CAS_SERVICE_ATTRIBUTE_NAME, context.getExternalContext().getSessionMap().get(CAS_SERVICE_ATTRIBUTE_NAME));

            AuthLinkInfo authInfo = authLinkManager.getPacketInfo(request);

            String principalCode = authInfo.getCountry() + authInfo.getCode();
            String firstName = getUnescapedNameField(authInfo.getFirstName());
            String lastName = getUnescapedNameField(authInfo.getLastName());

            TaraCredential credential = new TaraCredential(AuthenticationType.BankLink, principalCode, firstName, lastName);
            context.getFlowExecutionContext().getActiveSession().getScope().put(CasWebflowConstants.VAR_ID_CREDENTIAL, credential);

            logEvent(new StatisticsRecord(LocalDateTime.now(), getServiceClientId(context), getBankEnum(context), StatisticsOperation.SUCCESSFUL_AUTH));

            return new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS);
        } catch (Exception e) {
            logFailureEvent(context, e);
            throw e;
        }
    }

    private void logFailureEvent(RequestContext context, Exception e) {
        BankEnum bankEnum = getBankEnum(context);
        if (bankEnum != null)
            logEvent(new StatisticsRecord(LocalDateTime.now(), getServiceClientId(context), bankEnum, e.getMessage()));
    }

    private static BankEnum getBankEnum(RequestContext context) {
        return context.getExternalContext().getSessionMap().get(BANK_ENUM_ATTRIBUTE, BankEnum.class);
    }

    private static void addBankUrlToResponseCspFormActionDirective(RequestContext context, AuthLink banklink) {
        HttpServletResponse response = (HttpServletResponse) context.getExternalContext().getNativeResponse();
        CspHeaderUtil.addValueToExistingDirectiveInCspHeader(response, CspDirective.FORM_ACTION, banklink.getUrl());
    }

    protected static String getUnescapedNameField(String name) {
        if (StringUtils.isEmpty(name))
            throw new IllegalStateException("Name field cannot be empty!");

        return StringEscapeUtils.unescapeHtml4(name).toUpperCase();
    }
}
