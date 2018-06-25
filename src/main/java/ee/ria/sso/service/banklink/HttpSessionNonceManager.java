package ee.ria.sso.service.banklink;

import com.nortal.banklink.core.packet.NonceManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class HttpSessionNonceManager implements NonceManager {

    private final int nonceExpirationTimeInSeconds;

    @Override
    public String generateNonce() {
        HttpServletRequest httpServletRequest = getHttpServletRequest();

        String nonce = UUID.randomUUID().toString();
        LocalDateTime expirationTime = LocalDateTime.now().plusSeconds(nonceExpirationTimeInSeconds);
        HttpSession session = httpServletRequest.getSession(true);
        session.setAttribute(nonce, expirationTime);
        log.debug("New nonce added to session {} which expires at: {} ", nonce, expirationTime );

        return nonce;
    }

    @Override
    public boolean verifyNonce(String nonce) {
        HttpServletRequest httpServletRequest = getHttpServletRequest();
        HttpSession session = httpServletRequest.getSession(true);

        LocalDateTime expirationTime = (LocalDateTime)session.getAttribute(nonce);
        if (expirationTime != null) {
            return isValidNonce(nonce, session, expirationTime);
        } else {
            log.debug("Nonce '{}' not found in session!", nonce);
            return false;
        }
    }

    private boolean isValidNonce(String nonce, HttpSession session, LocalDateTime expirationTime) {
        session.removeAttribute(nonce);
        return expirationTime.isAfter(LocalDateTime.now());
    }

    private HttpServletRequest getHttpServletRequest() {
        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        Assert.notNull(servletRequestAttributes, "An instance of ServletRequestAttributes not found in RequestContext!");
        return servletRequestAttributes.getRequest();
    }
}
