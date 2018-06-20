# Integrators guide

## Configuration parameters
--------------------

The configuration of the TARA service is managed through a central configuration properties file - `application.properties`. In addition to Apereo CAS configuration properties described [here](https://apereo.github.io/cas/5.1.x/installation/Configuration-Properties.html) the `application.properties` can also include properties for TARA specific features. The following document describes the custom configuration properties available in TARA service.

<a href="banklink"/>
### Estonian banklinks

Table 1 - Enabling banklink feature in TARA


| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `banklinks.enabled` | N | Feature toggle for banklink functionality in TARA. Enables banklinks feature to be loaded when set to `true`, otherwise ignores all othe banklink related configuration. Defaults to `false`, if not specified. |

Table 2 - Generic banklink properties

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `banklinks.available-banks` | Y | A comma separated list of bank codes that determine which bank link(s) are displayed on the login page. Supported values in the list are: <ul><li>`seb`</li><li>`luminor`</li><li>`coop`</li><li>`swedbank`</li><li>`lhv`</li><li>`danske`</ul> For example:`seb,lhv,luminor`. <br>Note that adding a bank to this list, requires the further bank specific property configuration (see Table 3 for details) |
| `banklinks.keystore` | Y | Path to the keystore that hold bank keys. For example: `classpath:banklinkKeystore.p12`, when the file is to be accessed from the classpath or `file:/etc/cas/banklinkKeystore.p12` when the file is referenced in the local filesystem.  |
| `banklinks.keystore-type` | N | Keystore type. Defaults to `PKCS12` |
| `banklinks.keystore-pass` | Y | Keystore password. |
| `banklinks.return-url` | Y | HTTP URL for accepting the bank authentication response. Must reference the publicly available TARA `/login` url. |

Table 3 - Bank specific properties


| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `banklinks.bank.{0}.sender-id` | Y | Sender ID uniquely identifies the authentication request sender for the bank. |
| `banklinks.bank.{0}.receiver-id` | Y | Receiver ID is the bank's ID. |
| `banklinks.bank.{0}.url` | Y | An HTTP URL. Bank login url |
| `banklinks.bank.{0}.private-key-alias` | N | Private key alias in the keystore. If not defined, `{0}_priv` is used. |
| `banklinks.bank.{0}.private-key-pass` | N | Private key password in the keystore. Defaults to keystore password when not defined. |
| `banklinks.bank.{0}.auth-info-parser-class` | N | A class name that allows overriding the bank response parsing. The class must implement the `AuthLinkInfoParser` interface. By default, a standard parser is used. |
| `banklinks.bank.{0}.try-re-encodes` | N | A comma separated list of standard charset names. When configured with a list of valid character set names, the TARA retries a failing signature validation with reencoded response (usin all the character set's specified).  |
| `banklinks.bank.{0}.nonce-expires-in-seconds` | N | Specifies the nonce's Time-To-Live in seconds.  |

NB! Property placeholder `{0}` refers to a specific bank code (see property description for `banklinks.available-banks`).


Example:

````
banklinks.enabled = true
banklinks.available-banks=coop,lhv
banklinks.keystore=classpath:/banklink/banklinkKeystore-test.p12
banklinks.keystore-type=PKCS12
banklinks.keystore-pass=changeit
banklinks.return-url=https://<frontendhost/context>/cas/login

# COOP
banklinks.bank.coop.sender-id=RIA
banklinks.bank.coop.receiver-id=COOP
banklinks.bank.coop.url=https://www.testcoop.ee/banklinkurl

# LHV
banklinks.bank.lhv.sender-id=RIA
banklinks.bank.lhv.receiver-id=LHV
banklinks.bank.lhv.url=https://www.testlhv.ee/banklinkurl
````