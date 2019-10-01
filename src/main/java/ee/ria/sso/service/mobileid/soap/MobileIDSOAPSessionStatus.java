package ee.ria.sso.service.mobileid.soap;

import ee.ria.sso.service.mobileid.MobileIDSessionStatus;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class MobileIDSOAPSessionStatus implements MobileIDSessionStatus {

    private final boolean authenticationComplete;
}
