package ee.ria.sso.utils;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CountryCodeUtilTest {

    @Test
    public void validCountryCodesFormat() {
        assertTrue(CountryCodeUtil.isValidCountryCode("EE"));
        assertTrue(CountryCodeUtil.isValidCountryCode("EN"));
        assertTrue(CountryCodeUtil.isValidCountryCode("LT"));
        assertTrue(CountryCodeUtil.isValidCountryCode("RU"));
        assertTrue(CountryCodeUtil.isValidCountryCode("TT"));
        assertTrue(CountryCodeUtil.isValidCountryCode("XX"));
    }

    @Test
    public void invalidCountryCodeFormat() {
        assertFalse(CountryCodeUtil.isValidCountryCode("E"));
        assertFalse(CountryCodeUtil.isValidCountryCode("EEE"));
        assertFalse(CountryCodeUtil.isValidCountryCode("ee"));
        assertFalse(CountryCodeUtil.isValidCountryCode("Ee"));
        assertFalse(CountryCodeUtil.isValidCountryCode("E E"));
        assertFalse(CountryCodeUtil.isValidCountryCode(" EE"));
        assertFalse(CountryCodeUtil.isValidCountryCode("EE "));
        assertFalse(CountryCodeUtil.isValidCountryCode("--"));
        assertFalse(CountryCodeUtil.isValidCountryCode("##"));
        assertFalse(CountryCodeUtil.isValidCountryCode("E2"));
        assertFalse(CountryCodeUtil.isValidCountryCode(""));
        assertFalse(CountryCodeUtil.isValidCountryCode("  "));
        assertFalse(CountryCodeUtil.isValidCountryCode(null));
    }
}
