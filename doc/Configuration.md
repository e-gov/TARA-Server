# Integrators guide

## Configuration parameters
--------------------

The configuration of the TARA service is managed through a central configuration properties file - `application.properties`. In addition to Apereo CAS configuration properties described [here](https://apereo.github.io/cas/5.1.x/installation/Configuration-Properties.html) the `application.properties` can also include properties for TARA specific features. The following document describes the custom configuration properties available in TARA service.


<a name="id_card"></a>
### ID-card authentication

Table 1 - Enabling ID-card certificate validation

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `ocsp.enabled` | N | Enables ID-card certificate validation if set to `true`, otherwise ignores all other ocsp related configuration. Defaults to `false`, if not specified. |

Table 2 - Configuring ID-card OCSP 

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `ocsp.url` | N | HTTP URL of the OCSP service. Defaults to `http://demo.sk.ee/ocsp`, if not specified. |
| `ocsp.certificateDirectory` | N | Path to the directory of trusted CA certificates. Defaults to blank, if not specified. |
| `ocsp.certificates` | N | A comma separated list of trusted CA certificates in the form of `<common_name>:<file_name>`. Defaults to empty list, if not specified. |

Example:

````
ocsp.url=http://demo.sk.ee/ocsp
ocsp.certificateDirectory=/etc/ocspcerts/test
ocsp.certificates=TEST of ESTEID-SK 2011:TEST_of_ESTEID-SK_2011.crt,TEST of ESTEID-SK 2015:TEST_of_ESTEID-SK_2015.crt
ocsp.enabled=true
````


<a name="mobile_id"></a>
### Mobile-ID authentication

Table 3 - Configuring Mobile-ID

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `mobileID.countryCode` | N | Country of origin. ISO 3166-type 2-character country codes are used. Defaults to `EE`, if not specified.<br>For more information, see `CountryCode` query parameter in [DigiDocService Specification](http://sk-eid.github.io/dds-documentation/api/api_docs/#mobileauthenticate). |
| `mobileID.language` | N | Language for user dialog in mobile phone. 3-letters capitalized acronyms are used. Possible values: <ul><li>`EST`</li><li>`ENG`</li><li>`RUS`</li><li>`LIT`</li></ul> Defaults to `EST`, if not specified.<br>For more information, see `Language` query parameter in [DigiDocService Specification](http://sk-eid.github.io/dds-documentation/api/api_docs/#mobileauthenticate). |
| `mobileID.serviceName` | N | Name of the service – previously agreed with Application Provider and DigiDocService operator. Maximum length – 20 chars. Defaults to `Testimine`, if not specified.<br>For more information, see `ServiceName` query parameter in [DigiDocService Specification](http://sk-eid.github.io/dds-documentation/api/api_docs/#mobileauthenticate). |
| `mobileID.messageToDisplay` | N | Text displayed in addition to ServiceName and before asking authentication PIN. Maximum length is 40 bytes. In case of Latin letters, this means also a 40 character long text, but Cyrillic characters may be encoded by two bytes and you will not be able to send more than 20 symbols. Defaults to `''`, if not specified.<br>For more information, see `MessageToDisplay` query parameter in [DigiDocService Specification](http://sk-eid.github.io/dds-documentation/api/api_docs/#mobileauthenticate). |
| `mobileID.serviceUrl` | N | HTTP URL of the DigiDocService operator. Defaults to `https://tsp.demo.sk.ee`, if not specified. |

Example:

````
mobileID.countryCode=EE
mobileID.language=EST
mobileID.serviceName=Testimine
mobileID.messageToDisplay=Näita siin
mobileID.serviceUrl=https://tsp.demo.sk.ee
````


<a name="eidas"></a>
### eIDAS authentication

Table 4 - Configuring eIDAS authentication

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `eidas.serviceUrl` | N | HTTP base URL of the eIDAS-client microservice. Defaults to `http://localhost:8889`, if not specified. |
| `eidas.heartbeatUrl` | N | HTTP URL of the eIDAS-client microservice heartbeat endpoint. Affects TARA [heartbeat endpoint](#heartbeat). |
| `eidas.client.availableCountries` | N | A comma separated list of ISO 3166-1 alpha-2 country codes that determine which countries are displayed on the login page. If not set or if the list is empty, then the eIDAS authentication option is not displayed on the login page. |

Example:

````
eidas.serviceUrl=https://<eidas-client-host:port>
eidas.heartbeatUrl=https://<eidas-client-host:port>/heartbeat
eidas.client.availableCountries=EE,LT,LV,FI,NO,IT,IE
````


<a name="banklink"></a>
### Estonian banklinks

Table 5 - Enabling banklink feature in TARA


| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `banklinks.enabled` | N | Feature toggle for banklink functionality in TARA. Enables banklinks feature to be loaded when set to `true`, otherwise ignores all other banklink related configuration. Defaults to `false`, if not specified. |

Table 6 - Generic banklink properties

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `banklinks.available-banks` | Y | A comma separated list of bank codes that determine which bank link(s) are displayed on the login page. Supported values in the list are: <ul><li>`seb`</li><li>`luminor`</li><li>`coop`</li><li>`swedbank`</li><li>`lhv`</li><li>`danske`</ul> For example:`seb,lhv,luminor`. <br>Note that adding a bank to this list, requires further bank specific property configuration (see Table 7 for details) |
| `banklinks.keystore` | Y | Path to the keystore that holds bank keys. For example: `classpath:banklinkKeystore.p12`, when the file is to be accessed from the classpath or `file:/etc/cas/banklinkKeystore.p12` when the file is referenced in the local filesystem.  |
| `banklinks.keystore-type` | N | Keystore type. Defaults to `PKCS12` |
| `banklinks.keystore-pass` | Y | Keystore password. |
| `banklinks.return-url` | Y | HTTP URL for accepting the bank authentication response. Must reference the publicly available TARA `/login` url. |

Table 7 - Bank specific properties


| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `banklinks.bank.{0}.sender-id` | Y | Sender ID that uniquely identifies the authentication request sender to the bank. The sender ID is described in the specific bank's banklink agreement. |
| `banklinks.bank.{0}.receiver-id` | Y | Receiver ID uniquely identifies the bank who is the recipient of the authentication request. The receiver ID is described in the specific bank's banklink agreement. |
| `banklinks.bank.{0}.url` | Y | An HTTP URL that accepts login requests. Bank login url. |
| `banklinks.bank.{0}.public-key-alias` | N | Public key alias in the keystore. If not defined, `{0}` (the bank's code) is used. |
| `banklinks.bank.{0}.private-key-alias` | N | Private key alias in the keystore. If not defined, `{0}_priv` is used. |
| `banklinks.bank.{0}.private-key-pass` | N | Private key password in the keystore. Defaults to keystore password when not defined. |
| `banklinks.bank.{0}.auth-info-parser-class` | N | A class name that allows overriding the bank response parsing. The class must implement the `AuthLinkInfoParser` interface. By default, a standard parser is used. |
| `banklinks.bank.{0}.try-re-encodes` | N | A comma separated list of standard charset names. When configured with a list of valid character set names, the TARA retries a failing signature validation with re-encoded response (using all the character set's specified). By default, only the character set requested in authentication request is used. |
| `banklinks.bank.{0}.nonce-expires-in-seconds` | N | Specifies the nonce's Time-To-Live in seconds. Defaults to 3600 seconds (1 hour). |

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


<a name="smart-id"></a>
### Estonian Smart-ID

Table 8 - Enabling Smart-ID authentication feature in TARA

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `smart-id.enabled` | N | Feature toggle for authentication with Smart-ID in TARA. Enables this feature to be loaded if set to `true`, otherwise ignores all other Smart-ID related configuration. Defaults to `false`, if not specified. |

Table 9 - Other Smart-ID configuration properties (if Smart-ID is enabled)

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `smart-id.host-url` | Y | HTTP URL of the Smart-ID service. |
| `smart-id.relying-party-name` | Y | Name of the relying party according to the contract between Smart-ID service provider and the relying party. This field is case insensitive. |
| `smart-id.relying-party-uuid` | Y | UUID value of the relying party according to the contract between Smart-ID service provider and the relying party. |
| `smart-id.authentication-hash-type` | N | Type of the authentication hash that is used to generate the control code of an authentication request. Supported values are: <ul><li>`SHA256`</li><li>`SHA384`</li><li>`SHA512`</li></ul> Defaults to `SHA512`, if not specified. |
| `smart-id.authentication-consent-dialog-display-text` | Y | Description of the authentication request. Displayed on the consent dialog shown on the end user's device. |
| `smart-id.session-status-socket-open-duration` | N | Maximum duration in milliseconds a session status query is kept alive. Defaults to `3000`, if not specified. |
| `smart-id.timeout-between-session-status-queries` | N | Timeout in milliseconds between consecutive session status queries. Defaults to `3000`, if not specified. |
| `smart-id.read-timeout` | N | Maximum total time in milliseconds to be spent on status queries during a session. Defaults to `30000`, if not specified. <br>This value should not be smaller than `smart-id.session-status-socket-open-duration`! |
| `smart-id.connection-timeout` | N | Maximum time spent in milliseconds on waiting for connection with Smart-ID service provider. Defaults to `5000`, if not specified. |
| `smart-id.trusted-ca-certificates-location` | Y | Path to the location of the trusted CA certificates. In case the certificate files are to be loaded from classpath, this path should be prefixed with `classpath:`. In case the certificate files are to be loaded from disk, this path should be prefixed with `file:`. |
| `smart-id.trusted-ca-certificates` | Y | A comma separated list of the names of the files of the trusted CA certificates. These certificates are used to validate the user certificated returned by the Smart-ID service. |

Example:

````
smart-id.enabled=true
smart-id.host-url=https://sid.demo.sk.ee/smart-id-rp/v1/
smart-id.relying-party-name=DEMO
smart-id.relying-party-uuid=00000000-0000-0000-0000-000000000000
smart-id.authentication-hash-type=SHA512
smart-id.authentication-consent-dialog-display-text=TEST
smart-id.session-status-socket-open-duration=3000
smart-id.timeout-between-session-status-queries=3000
smart-id.read-timeout=30000
smart-id.connection-timeout=5000
smart-id.trusted-ca-certificates-location = file:/etc/ocsp
smart-id.trusted-ca-certificates = TEST_1.crt,TEST_1.crt
````

More information about Estonian Smart-ID can be obtained from [here](https://github.com/SK-EID/smart-id-documentation).


<a name="heartbeat"></a>
### Heartbeat endpoint

TARA heartbeat endpoint is a Spring Boot Actuator endpoint and thus is configured as described [here](https://docs.spring.io/spring-boot/docs/1.5.3.RELEASE/reference/html/production-ready-endpoints.html), while also taking into consideration CAS specific configuration properties as described [here](https://apereo.github.io/cas/5.1.x/installation/Configuration-Properties.html#spring-boot-endpoints).

Table 10 - Configuring heartbeat endpoint in TARA

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `endpoints.heartbeat.*` | N | Spring Boot specific actuator configuration. |
| `endpoints.heartbeat.timeout` | N | Maximum time to wait on status requests made to systems that TARA is depending on, in seconds. Defaults to 3 seconds. |

Table 11 - Heartbeat endpoints on systems TARA is depending on

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `eidas.heartbeatUrl` | N | HTTP URL of the eIDAS-client microservice heartbeat endpoint. If set, the eIDAS-client status affects the overall reported status of TARA-server. |

Example configuration with **heartbeat** endpoint enabled, accessible without authentication and from all IP-addresses, and configure eIDAS-client **heartbeat** URL:

````
endpoints.heartbeat.enabled=true
endpoints.heartbeat.sensitive=false

# Allow access from all IP-addresses
cas.adminPagesSecurity.ip=.+

# Configure eIDAS-client heartbeat url
eidas.heartbeatUrl=https://<eidas-client-host:port>/heartbeat
````


<a name="test_environment_warning"></a>
### Test environment warning message

Table 12 - Configuring TARA login page to show a warning message about it being run against test services

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `env.test.message` | N | Warning message to show. No warning displayed if not set. |

Example:

````
env.test.message=Tegemist on testkeskkonnaga ja autentimiseks vajalik info on <a href="https://e-gov.github.io/TARA-Doku/Testimine#testimine-testnumbrite-ja-id-kaardiga" class="alert-link">TARA dokumentatsioonis</a>!
````