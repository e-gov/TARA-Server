package ee.ria.sso.service.idcard;

import lombok.Getter;

@Getter
public class OCSPValidationException extends RuntimeException {

    private final CertificateStatus status;

    private OCSPValidationException(CertificateStatus status) {
        super(String.format("Invalid certificate status <%s> received", status));
        this.status = status;
    }

    public static OCSPValidationException of(CertificateStatus certificateStatus) {
        return new OCSPValidationException(certificateStatus);
    }
}
