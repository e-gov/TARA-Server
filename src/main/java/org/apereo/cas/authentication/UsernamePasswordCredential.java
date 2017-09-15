package org.apereo.cas.authentication;

/**
 * Created by serkp on 8.09.2017.
 */

import java.io.Serializable;

import org.springframework.webflow.core.collection.AttributeMap;

import com.codeborne.security.mobileid.MobileIDSession;

public class UsernamePasswordCredential implements Credential, Serializable {
	public static final String AUTHENTICATION_ATTRIBUTE_PASSWORD = "credential";
	private static final long serialVersionUID = -700605081472810939L;

	AttributeMap attributeMap;

	private String username;
	private String password;

	private String firstName;
	private String lastName;
	private String mobileNumber;
	private String personalCode;


	public UsernamePasswordCredential() {
	}


	public UsernamePasswordCredential(String username, MobileIDSession session) {
		this.username = username;

		setFirstName(session.firstName);
		setLastName(session.lastName);
		setMobileNumber(username);
		setPersonalCode(session.personalCode);
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getMobileNumber() {
		return mobileNumber;
	}

	public void setMobileNumber(String mobileNumber) {
		this.mobileNumber = mobileNumber;
	}

	public String getPersonalCode() {
		return personalCode;
	}

	public void setPersonalCode(String personalCode) {
		this.personalCode = personalCode;
	}


	public String getPassword() {
		return this.password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getUsername() {
		return this.username;
	}

	public void setUsername(String userName) {
		this.username = userName;
	}

	public String getId() {
		return this.mobileNumber;
	}

	public String toString() {
		return this.mobileNumber;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;

		UsernamePasswordCredential that = (UsernamePasswordCredential) o;

		if (!mobileNumber.equals(that.mobileNumber))
			return false;
		return personalCode.equals(that.personalCode);
	}

	@Override
	public int hashCode() {
		int result = mobileNumber.hashCode();
		result = 31 * result + personalCode.hashCode();
		return result;
	}

	public AttributeMap getAttributeMap() {
		return attributeMap;
	}

	public void setAttributeMap(AttributeMap attributeMap) {
		this.attributeMap = attributeMap;
	}
}
