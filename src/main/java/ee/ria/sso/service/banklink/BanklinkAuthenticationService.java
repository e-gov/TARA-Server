package ee.ria.sso.service.banklink;

import com.nortal.banklink.authentication.AuthLink;
import com.nortal.banklink.authentication.AuthLinkInfo;
import com.nortal.banklink.authentication.AuthLinkManager;
import com.nortal.banklink.core.packet.Packet;
import ee.ria.sso.authentication.AuthenticationType;
import ee.ria.sso.authentication.BankEnum;
import ee.ria.sso.authentication.TaraAuthenticationException;
import ee.ria.sso.authentication.credential.TaraCredential;
import ee.ria.sso.common.AbstractService;
import ee.ria.sso.config.TaraResourceBundleMessageSource;
import ee.ria.sso.statistics.StatisticsHandler;
import ee.ria.sso.statistics.StatisticsOperation;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;

@ConditionalOnProperty("banklinks.enabled")
@Service
public class BanklinkAuthenticationService extends AbstractService {

    private static final String SERVICE_ATTRIBUTE = "service";

    private final StatisticsHandler statistics;
    private final AuthLinkManager authLinkManager;

    public BanklinkAuthenticationService(TaraResourceBundleMessageSource messageSource, StatisticsHandler statistics, AuthLinkManager authLinkManager) {
        super(messageSource);
        this.statistics = statistics;
        this.authLinkManager = authLinkManager;
    }

    public Event startLoginByBankLink(RequestContext context) {
        try {
            String bankCode = context.getRequestParameters().get("bank");
            if (StringUtils.isEmpty(bankCode)) {
                throw new IllegalStateException("Requested bank parameter cannot be null nor empty!");
            }

            BankEnum bankEnum = BankEnum.valueOf(bankCode.toUpperCase());
            AuthLink banklink = authLinkManager.getBankLink(bankEnum.getAuthLinkBank());
            context.getRequestScope().put("url", banklink.getUrl());

            Packet outgoingPacket = banklink.createOutgoingPacket();
            outgoingPacket.setParameter("VK_LANG", LocaleContextHolder.getLocale().getISO3Language().toUpperCase());
            context.getRequestScope().put("packet", outgoingPacket);
            context.getExternalContext().getSessionMap().put(SERVICE_ATTRIBUTE, context.getFlowScope().get(SERVICE_ATTRIBUTE));
            this.statistics.collect(LocalDateTime.now(), context, AuthenticationType.BankLink, StatisticsOperation.START_AUTH);

            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, AuthenticationType.BankLink, e);
        }
    }

    public Event checkLoginForBankLink(RequestContext context) {
        try {
            HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getNativeRequest();

            AuthLinkInfo authInfo = authLinkManager.getPacketInfo(request);

            String principalCode = authInfo.getCountry() + authInfo.getCode();
            String firstName = getUnescapedNameField(authInfo.getFirstName());
            String lastName = getUnescapedNameField(authInfo.getLastName());

            TaraCredential credential = new TaraCredential(AuthenticationType.BankLink, principalCode, firstName, lastName);
            context.getFlowExecutionContext().getActiveSession().getScope().put("credential", credential);
            context.getFlowScope().put(SERVICE_ATTRIBUTE, context.getExternalContext().getSessionMap().get(SERVICE_ATTRIBUTE));
            this.statistics.collect(LocalDateTime.now(), context, AuthenticationType.BankLink, StatisticsOperation.SUCCESSFUL_AUTH);

            return new Event(this, "success");
        } catch (Exception e) {
            throw this.handleException(context, AuthenticationType.BankLink, e);
        }
    }

    private RuntimeException handleException(RequestContext context, AuthenticationType type, Exception exception) {
        clearFlowScope(context);
        this.statistics.collect(LocalDateTime.now(), context, type, StatisticsOperation.ERROR, exception.getMessage());
        String localizedErrorMessage = this.getMessage("message.general.error");
        return new TaraAuthenticationException(localizedErrorMessage, exception);
    }

    private static void clearFlowScope(RequestContext context) {
        context.getFlowScope().clear();
        context.getFlowExecutionContext().getActiveSession().getScope().clear();
    }

    protected static String getUnescapedNameField(String name) {
        if (StringUtils.isEmpty(name))
            throw new IllegalStateException("Name field cannot be empty!");

        return StringEscapeUtils.unescapeHtml4(name).toUpperCase();
    }
}
