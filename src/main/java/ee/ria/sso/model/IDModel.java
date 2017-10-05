package ee.ria.sso.model;


/**
 * Created by serkp on 3.10.2017.
 */
public class IDModel {

    private String serialNumber;
    private String givenName;
    private String surname;

    public IDModel(String serialNumber, String givenName, String surname) {
        this.serialNumber = serialNumber;
        this.givenName = givenName;
        this.surname = surname;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

}
