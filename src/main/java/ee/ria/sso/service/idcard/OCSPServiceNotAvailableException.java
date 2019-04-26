package ee.ria.sso.service.idcard;

public class OCSPServiceNotAvailableException extends RuntimeException {

    public OCSPServiceNotAvailableException(String message) {
        super(message);
    }

    public OCSPServiceNotAvailableException(String message, Exception e) {
        super(message,e);
    }
}
