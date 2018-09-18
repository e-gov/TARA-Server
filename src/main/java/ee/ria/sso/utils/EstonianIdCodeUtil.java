package ee.ria.sso.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class EstonianIdCodeUtil {

    public static final String ESTONIAN_ID_CODE_REGEX = "[1-6][0-9]{2}((0[1-9])|(1[0-2]))((0[1-9])|([1-2][0-9])|(3[0-1]))[0-9]{4}";
    public static final String GENERIC_ESTONIAN_ID_CODE_REGEX = "(|EE|PNOEE-)(" + ESTONIAN_ID_CODE_REGEX + ")";
    public static final String EE_PREFIXED_ESTONIAN_ID_CODE_REGEX = "EE" + ESTONIAN_ID_CODE_REGEX;

    public static boolean isEEPrefixedEstonianIdCode(String idCode) {
        return idCode.matches(EE_PREFIXED_ESTONIAN_ID_CODE_REGEX);
    }

    public static String extractDateOfBirthFromEEPrefixedEstonianIdCode(String idCode) {
        final int sexAndCentury = Integer.parseUnsignedInt(idCode.substring(2, 3));
        final int birthYear = (1800 + ((sexAndCentury - 1) >>> 1) * 100) +
                Integer.parseUnsignedInt(idCode.substring(3, 5));

        final int birthMonth = Integer.parseUnsignedInt(idCode.substring(5, 7));
        final int birthDay = Integer.parseUnsignedInt(idCode.substring(7, 9));

        return String.format("%04d-%02d-%02d", birthYear, birthMonth, birthDay);
    }

    public static String getEEPrefixedEstonianIdCode(String idCode) {
        final Matcher matcher = Pattern.compile(GENERIC_ESTONIAN_ID_CODE_REGEX).matcher(idCode);

        if (matcher.matches()) {
            return "EE" + matcher.group(2);
        } else {
            throw new IllegalArgumentException("Invalid Estonian identity code");
        }
    }

    private EstonianIdCodeUtil() {}

}
