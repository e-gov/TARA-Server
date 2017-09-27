package ee.ria.sso;

/**
 * Created by serkp on 8.09.2017.
 */
public enum AttributeConstant {

	FIRST_NAME("firstName"),
	LAST_NAME("lastName"),
	MOBILE_NUMBER("mobileNumber"),
	PERSONAL_CODE("personalCode");

	AttributeConstant(String key) {
		this.key = key;
	}

	private String key;

	public String getKey() {
		return key;
	}
}