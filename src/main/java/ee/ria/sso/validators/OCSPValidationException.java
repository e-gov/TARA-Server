package ee.ria.sso.validators;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class OCSPValidationException extends RuntimeException {

    private final CertificateStatus status;

    private OCSPValidationException(CertificateStatus status) {
        super(String.format("Invalid certificate status <%s> received", status));
        this.status = status;
    }

    public OCSPValidationException(Exception exception) {
        super(exception);
        this.status = CertificateStatus.ERROR;
    }

    public static OCSPValidationException of(CertificateStatus certificateStatus) {
        return new OCSPValidationException(certificateStatus);
    }

    public static OCSPValidationException of(Exception exception) {
        return new OCSPValidationException(exception);
    }

    /*
     * ACCESSORS
     */

    public CertificateStatus getStatus() {
        return status;
    }

}
