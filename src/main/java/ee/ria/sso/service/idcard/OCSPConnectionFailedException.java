package ee.ria.sso.service.idcard;

public class OCSPConnectionFailedException extends RuntimeException {

    public OCSPConnectionFailedException(Exception exception) {
        super(exception);
    }
}
