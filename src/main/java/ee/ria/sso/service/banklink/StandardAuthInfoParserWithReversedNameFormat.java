package ee.ria.sso.service.banklink;

import com.nortal.banklink.authentication.link.standard.IPizzaStandardAuthInfoParser;
import org.apache.commons.text.WordUtils;

import java.util.Arrays;

public class StandardAuthInfoParserWithReversedNameFormat extends IPizzaStandardAuthInfoParser {

    public static final String FIRSTNAME_LASTNAME_DELIMITER = " ";

    @Override
    protected String[] normalizeName(String name) {
        String[] parts = name.split(FIRSTNAME_LASTNAME_DELIMITER);
        String firstNames = String.join(" ", Arrays.copyOf(parts, parts.length - 1));
        String lastName = parts[parts.length - 1];
        return new String[]{WordUtils.capitalizeFully(firstNames), WordUtils.capitalizeFully(lastName)};
    }
}
