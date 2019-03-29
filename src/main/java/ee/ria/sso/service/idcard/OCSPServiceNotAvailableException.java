package ee.ria.sso.service.idcard;

public class OCSPServiceNotAvailableException extends RuntimeException {

    public OCSPServiceNotAvailableException(Exception exception) {
        super(exception);
    }

    public OCSPServiceNotAvailableException(String message) {
        super(message);
    }
}
