package org.apereo.cas.authentication;

/**
 * Created by serkp on 8.09.2017.
 */


import java.io.Serializable;

import com.codeborne.security.mobileid.MobileIDSession;
import org.springframework.webflow.core.collection.AttributeMap;

import ee.ria.sso.model.IDModel;


/**
 * @author Priit Serk: priit.serk@gmail.com
 * @since 5.1.4
 */

@Deprecated
public class UsernamePasswordCredential implements Credential, Serializable {
	private static final long serialVersionUID = -700605081472810939L;

	private AttributeMap attributeMap;

	private String username;
	private String password;

	private String givenName;
	private String familyName;
	private String principalCode;
	private String authenticationType;
	private String mobileNumber;

	public UsernamePasswordCredential() {
	}

	public UsernamePasswordCredential(String username, MobileIDSession session) {
		this.username = username;
		setGivenName(session.firstName);
		setFamilyName(session.lastName);
		setPrincipalCode(session.personalCode);
		setMobileNumber(username);
		setAuthenticationType("MID");
	}

	public UsernamePasswordCredential(String username, IDModel session) {
		this.username = username;
		setGivenName(session.getGivenName());
		setFamilyName(session.getSurname());
		setPrincipalCode(session.getSerialNumber());
		setAuthenticationType("ID");
	}


	public String getGivenName() {
		return givenName;
	}

	public void setGivenName(String givenName) {
		this.givenName = givenName;
	}

	public String getFamilyName() {
		return familyName;
	}

	public void setFamilyName(String familyName) {
		this.familyName = familyName;
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

	public String getPrincipalCode() {
		return principalCode;
	}

	public void setPrincipalCode(String principalCode) {
		this.principalCode = principalCode;
	}

	public String getId() {
		return this.principalCode;
	}

	public String toString() {
		return this.principalCode;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		UsernamePasswordCredential that = (UsernamePasswordCredential) o;

		return principalCode != null ? principalCode.equals(that.principalCode)
				: that.principalCode == null;
	}

	@Override
	public int hashCode() {
		return principalCode != null ? principalCode.hashCode() : 0;
	}

	public String getAuthenticationType() {
		return authenticationType;
	}

	public void setAuthenticationType(String authenticationType) {
		this.authenticationType = authenticationType;
	}

	public AttributeMap getAttributeMap() {
		return attributeMap;
	}

	public void setAttributeMap(AttributeMap attributeMap) {
		this.attributeMap = attributeMap;
	}

	public String getMobileNumber() {
		return mobileNumber;
	}

	public void setMobileNumber(String mobileNumber) {
		this.mobileNumber = mobileNumber;
	}
}
