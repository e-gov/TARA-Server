package ee.ria.sso.utils;

public final class EstonianIdCodeUtil {

    public static final String ESTONIAN_ID_CODE_REGEX = "EE[1-6][0-9]{2}((0[1-9])|(1[0-2]))((0[1-9])|([1-2][0-9])|(3[0-1]))[0-9]{4}";

    public static boolean isEstonianIdCode(String idCode) {
        return idCode.matches(ESTONIAN_ID_CODE_REGEX);
    }

    public static String extractDateOfBirthFromEstonianIdCode(String idCode) {
        final int sexAndCentury = Integer.parseUnsignedInt(idCode.substring(2, 3));
        final int birthYear = (1800 + ((sexAndCentury - 1) >>> 1) * 100) +
                Integer.parseUnsignedInt(idCode.substring(3, 5));

        final int birthMonth = Integer.parseUnsignedInt(idCode.substring(5, 7));
        final int birthDay = Integer.parseUnsignedInt(idCode.substring(7, 9));

        return String.format("%04d-%02d-%02d", birthYear, birthMonth, birthDay);
    }

    private EstonianIdCodeUtil() {}

}
