package ee.ria.sso.service.mobileid.rest;

import ee.ria.sso.service.mobileid.MobileIDSessionStatus;
import ee.sk.mid.rest.dao.MidSessionStatus;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class MobileIDRESTSessionStatus implements MobileIDSessionStatus {

    private final boolean authenticationComplete;
    private final MidSessionStatus wrappedSessionStatus;
}
