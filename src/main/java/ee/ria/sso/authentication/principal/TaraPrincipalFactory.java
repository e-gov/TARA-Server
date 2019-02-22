package ee.ria.sso.authentication.principal;

import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@NoArgsConstructor
@EqualsAndHashCode
public class TaraPrincipalFactory implements PrincipalFactory {

    private static final long serialVersionUID = 1L;

    @Override
    public Principal createPrincipal(String id) {
        throw new IllegalArgumentException("Attributes are mandatory when creating principal");
    }

    public Principal createPrincipal(String id, Map<String, Object> attributes) {
        Assert.notEmpty(attributes, "No attributes found when creating principal");
        return new TaraPrincipal(id, attributes);
    }

    public static Principal createPrincipal(TicketGrantingTicket tgt) {
        Assert.notNull(tgt, "TGT cannot be null!");
        final Principal principal = tgt.getAuthentication().getPrincipal();
        Assert.notNull(tgt, "No authentication associated with TGT!");

        Map<String, Object> attributes = principal.getAttributes()
                .entrySet()
                .stream()
                .filter(
                        entry -> entry.getValue() instanceof List
                                && !((List)entry.getValue()).isEmpty()
                ).collect(
                        Collectors.toMap(
                                entry -> entry.getKey().toLowerCase(),
                                entry -> ((List)entry.getValue()).stream().findFirst().get()
                        )
                );
        return new TaraPrincipal(principal.getId(), attributes);
    }
}
