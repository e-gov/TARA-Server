_CAS tarkvaras tehtud kohanduste ja täienduste kirjeldus._

# Integrator's guide

- [1. Logging](#logging)
  * [1.1 Log configuration](#log_conf)
  * [1.2 Log files](#log_files)
  * [1.3 Remote syslog server](#tara_syslog)
  * [1.4 TARA audit trail events](#audit_events)  
  * [1.5 Tara-Stat](#tara_stat_log)  
- [2. TARA specific configuration parameters](#configuration_parameters)
  * [2.1 ID-Card authentication](#id_card)
  * [2.2 Mobile-ID authentication](#mobile_id)
  * [2.3 eIDAS authentication](#eidas)
  * [2.4 Banklink authentication](#banklink)
  * [2.5 Smart-ID authentication](#smart-id)
  * [2.6 Heartbeat endpoint](#heartbeat)
  * [2.7 Content Security Policy](#security_csp)
  * [2.8 Tara-Stat service](#tara_stat)
  * [2.9 Test environment warning message](#test_environment_warning)
  * [2.10 Audit logging](#audit_logging)
  * [2.11 Enabling additional OpenID Connect endpoints](#oidc_optional_endpoints)
  * [2.12 Client secret handling](#oidc_client_secret)
  * [2.13 Always force re-authentication](#oidc_force_reauthentication)
  * [2.14 Default authentication methods on login page](#default_auth_methods)
  * [2.15 Assigning eIDAS level of assurance to domestic authentication methods](#eidas_auth_methods_loa)
- [3. TARA truststore](#tara_truststore)
  * [3.1 Mobile-ID CA certs](#dds_ca_certs)
  * [3.2 Smart-ID CA certs](#smart-id_ca_certs)
- [4. CAS properties](#cas_properties)
  * [4.1 Showing service's name](#cas_service_name)
  * [4.2 Translating service's name](#cas_service_name_translation)
  * [4.3 Showing service's short name](#cas_service_short_name)
  * [4.4 Translating service's short name](#cas_service_short_name_translation)

<a name="logging"></a>
## 1. Logging

<a name="log_conf"></a>
### 1.1 Configuration

Logging in TARA is handled by [Log4j2 framework](https://logging.apache.org/log4j/2.x/index.html) which can be configured by using an [xml configuration file](https://logging.apache.org/log4j/2.x/manual/configuration.html) (`log4j2.xml`).

By default TARA uses an [example configuration](../src/main/webapp/WEB-INF/classes/log4j2.xml) embedded in the service application, that contains configuration samples for using local log files and remote syslog server (needs further configuration).

Logging behavior can be customized in the following ways:

1. By providing your own configuration file and overriding the default file. Using the property `logging.config` in the `application.properties` (see CAS documentation for further logging implementation [details](https://apereo.github.io/cas/5.3.x/installation/Logging.html).)
    
    Example:
    ````
    logging.config=file:/etc/cas/config/log4j2.xml
    ````

    Note that CAS monitors the `log4j2.xml` file changes and reloads the configuration automatically accordingly.

2. By overriding the parameter values in the default `log4j2.xml` configuration file with system properties (see table 1.1.1)

Table 1.1.1 - configurable parameters in log configuration 

| **Property**       | **Description** | **Default** |
| :---------------- | :---------- | :-----------|
| **tara.log.dir** | Output directory for the log files | `/var/log/cas` |
| **tara.log.level** | Controls the detail level of the main event stream (`cas.log`).  | `info` |
| **tara.console.level** | Console log verbosity level | `off` |

Parameters in table 1.1.1 can be overridden when needed by providing the parameter as a system property on service startup.

Example:
````
export JAVA_OPTS="-Dtara.log.level=debug -Dtara.console.level=off"
````


<a name="log_files"></a>
### 1.2 Log files

By default, all log files are written to the local filesystem `/var/log/cas` and a log rotation is performed daily. The location of the files can be overridden either by providing a parameter `-Dtara.log.dir=<logdir>` during TARA startup or overriding the `log4j2.xml` file.

Log files names correspond to pattern logfile-%d{yyyy-MM-dd}.log and the names are not modified during log rotation. Example: cas_audit-2025-01-31.log. Logs are rolled over at midnight by creating a new file with the pattern. Old files are kept uncompressed in the same directory for seven days.

List of log files created by TARA on initialization:

| **Type of log**        | **Contents description** |
| :---------------- | :---------- |
| **[cas.log](Configuration.md#cas_log)** | TARA's main log event stream that contains all authentication attempts and general system events (session expirations and cleanup events, etc).  |
| **[cas_error.log](Configuration.md#cas_error_log)** | Errors with technical and detailed stack traces. |
| **[cas_audit.log](Configuration.md#cas_audit_log)** | Pre-defined events derived from user actions to be audited for security purposes. |
| **stats.log** | Simplified CSV formatted authentication statistics. See [statistics specification](https://e-gov.github.io/TARA-Doku/Statistika) for log record specification and further details. |
| **perfStats.log** | Performance metrics. Periodically prints report that consists of brief memory, thread allocation and ticket stats. Kept for one day by default |


<a name="cas_log"></a>
#### cas.log

Events are recorded in the json format, separated by the newline character `\n`.

Log event structure:

| **Field**       | **Description** | **Always present** |
| :---------------- | :---------- | :---------- |
| **date** | Event date and time in ISO-8601 compatible format. Example: `2018-08-17T18:23:48,543` | Y |
| **level** | Level of importance. Possible values (from the least serios to most serious): `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL` | Y |
| **requestId** | Unique 16 character alphanumeric string to identify the user's request. Empty when the event was generated by CAS itself. | N |
| **sessionId** | Session id hash. Base64 encoded session identifier (sha256 hash from of the session id). Empty when the event was generated by CAS itself. | N |
| **logger** | Logger name | Y |
| **thread** | Thread name | Y |
| **message** | Log message using the JSON encoding format, this follows the escaping rules specified by RFC 4627 section 2.5. | Y |


Example:
````
{"date":"2018-08-19T17:11:25,373", "level":"ERROR", "requestId":"LPBA1Q0KKC8DNJSK", "sessionId":"xB4WXSgEJgFIUtGLjq0bTswIzgrWTsUX-ik6LrpKQ1w=", "logger":"ee.ria.sso.flow.action.AbstractAuthenticationAction", "thread":"http-nio-8081-exec-4", "message":"Authentication failed: Sertifikaati ei leitud! Kas Teie ID-kaart on kaardilugejasse sisestatud?"}
````

<a name="cas_error_log"></a>
#### cas_error.log

Events are recorded in the json format, separated by the newline character `\n`.

Log event structure:

| **Field**       | **Description** | **Always present** |
| :---------------- | :---------- | :---------- |
| **date** | Event date and time in ISO-8601 compatible format. Example: `2018-08-17T18:23:48,543` | Y |
| **level** | Level of importance. Either: `ERROR` or `FATAL` | Y |
| **requestId** | Unique 16 character alphanumeric string to identify the user's request. Empty when the event was generated by CAS itself. | N |
| **sessionId** | Session id hash. Base64 encoded session identifier (sha256 hash from of the session id). Empty when the event was generated by CAS itself.   | N |
| **logger** | Logger name | Y |
| **thread** | Thread name | Y |
| **throwable** | Exception trace using the JSON encoding format, this follows the escaping rules specified by RFC 4627 section 2.5. Empty when no trace was provided. | N |

Example:
````
{"date":"2018-08-19T17:11:25,373", "level":"ERROR", "requestId":"LPBA1Q0KKC8DNJSK", "sessionId":"xB4WXSgEJgFIUtGLjq0bTswIzgrWTsUX-ik6LrpKQ1w=", "throwable":" ee.ria.sso.authentication.TaraAuthenticationException: Sertifikaati ei leitud! Kas Teie ID-kaart on kaardilugejasse sisestatud?\u000A\u0009at ee.ria.sso.service.idcard.IDCardAuthenticationService.handleException(IDCardAuthenticationService.java:120)\u000A\u0009at ........ more\u000A"}
````



<a name="cas_audit_log"></a>
#### cas_audit.log

Events are recorded in the json format, separated by the newline character `\n`.

Log event structure:

| **Field**       | **Description** |
| :---------------- | :---------- |
| **request** | Request method and URL in the form of `METHOD protocol://server_name:server_port/request_uri`. For example `POST https://tara.dev:443/login`. |
| **requestId** | Unique 16 character alphanumeric string to identify the user's request. Empty when the event was generated by CAS itself. |
| **sessionId** | Session id hash. Base64 encoded session identifier (sha256 hash from of the session id). Empty when the event was generated by CAS itself.   |
| **message** | JSON object (escaped by the rules specified by RFC 4627 section 2.5). <br><br>List of fields contained in the JSON object (all mandatory): <br><br>* **action** - Audit event code, that describes the action in the audit trail. See TARA related events [here](Configuration.md#audit_events).<br>* **who** - User ID. Principal code if authenticated, otherwise `audit:unknown`<br>* **what** - Custom message related to the event<br>* **when** - Event date and time in ISO-8601 compatible format. Example: `2018-08-17T18:23:48,543`<br>* **clientIpAddress** - Client IP<br>* **serverIpAddress** - Server IP<br>* **application** - Server instance name from the application configuration parameter `cas.audit.appCode`. Defaults to `CAS`. |

Example of unescaped audit message:
````
{
	"action": "AUTHENTICATION_EVENT_TRIGGERED",
	"who": "audit:unknown",
	"what": "[event=success,timestamp=Sun Aug 19 13:45:25 GMT 2018,source=RankedAuthenticationProviderWebflowEventResolver]",
	"when": "2018-08-19T17:11:25,373",
	"clientIpAddress": "172.10.0.1",
	"serverIpAddress": "172.10.0.2",
	"application": "TARA-INSTANCE-3"
}
````

Example - a failed ID-Card authentication:
````
{"request":"POST https://tara.dev:443/login", "requestId":"IJGV893YKFUFS6QJ", "sessionId":"KGDmOFhnQhMSdwdEB3zUdio0DfNe9qOb_5nLGtVjod4=", "message":"{\"action\":\"ESTEID_AUTHENTICATION_FAILED\",\"who\":\"audit:unknown\",\"what\":\"Supplied parameters: map['service' -> 'https://tara.dev/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.arendus.kit:8451/oauth/response', 'execution' -> '31304995-1519-4c99-b43a-903511f3e40e_ZXlKaGJHY2lPaUpJVXpVeE1pSjkuYjBoSlIxbFBRWFpVYmt4UmVrUmxZazVEU1RoblV6bHBWblYyWXpaU2NWWTFXVzFJTmpCclRWSnJiWGRzTTBkbGVqWm5hM1pKU1V4dFRqUmtWbk5qVkVSeGJVWjJPR0pxSzFKSE9XMXdkRUo2ZW1GTFZFRTBXbkJDV1ZKT016azRVMmxUU25sTk5HaEhSVEYxZUZSek1USnFlVE5KVHpOMFFYWktNVlJwY2tWU09VSmxkMDFaWlc1RlVrcG9lbXhJUkhCeGJFSmhiV0o0WjJSWGFHNDNaVFE0ZVZOT1prbHJWa2xNYVZWUU5HOXhZMk0wTTFOQlZtTlNlVmh6VTNobmR6WkZZa2R6ZUhkaGIxZExOR1ZHWkVaWllYbEVjbFpEV1dVclNIcG5VRzV2WlVOaGFHcDRVRTlDZUVoMk4zWkZUaTlMZVdWR2NHbEtSbE5wZVVKamJuQTRiVVpaWTNobWRrNVJkSEp3UWpCWFpEaDFiQzl1V0c4NVFqZGtjaXRYUW01WmREUm9RMVJWY0hoNVluQkdTV0o2ZFU5NVZtWnJTbGRxVUZad1JtUllTM050T1hCWGJGcHBhRTlaTTNSM2RFRTRUa1E1YVZkMWFtNXBWRkJzVUU1UlFtZFNOeXQ0ZG5WNU0yZHpaMHh0T1cxclNrOXhTME12ZG1sTVJYTkJRMVV3WlZOYWVqVjRVV3R5Y2t0MllsUjZabmN4VUhwMlkyWlJaMkp4YnpCaGVHOWxWVWhKUm1sb01sa3lUV1ZTVG1Kc1ExRlVZMlZXVFRac1RYcG5RMmh6VDFaNVRYSjRTelpCTUdoNlZsaHJiV1V3YlVFeWRtcHZNM3BvU25WM01WaHFVMFJ0YkUxU05WVlBXUzgzVXpSTGJtdFVVbTQzY1hOM01qaFFkemRLWkRSYUsyYzVTeXRTVDJOb1dEVTVVMnRwWlZaRU9EQTBSR05yUzA5aVdIRXlOMUIxUmlzM01YTnhaMDlZZVVFemEwMDRVemQySzJWb09FUkNPRWhsWlRaSFVTdGlWRlZEUVhKeFNuZG1ObXg2ZFc0NE9GWnNTa1l3T1VSbFltVm5UMVJyYlRWcVNrNXRVazlRTTA1eU1ETmpVRWxtUzFOd2MydGFjVEkwYzNablRHVTNhSFowV0Vjck5YWktkbFJTTjJwbVMydExWbVYwTlVwelNrdE5SVzlCTms1YWJHMTNhRlJIUzJOaWJFY3hlazFxT1hkTFprZzVRMU5NUWxweFlUQk9VMWRwUVhOaE1qWmhLMDluVG1wb2VrTlBaMWhPVGpOQlZXZGhSbWxQZG1odVJuWXpVRzlTY1ZKQk5IQXpTVUZ4VGpkVGVVRnhiU3M1ZFhwdVJ6bEJORGhzVGtGSUsxWmlOMkVyUjFkamMxRk9RakpUVW5WbmRsRkVjVmhOUTNWMWRVRXlReXM1T1VsT2RISkpVVGhWWkhFd1ZFaERWazUwT0ZkVlVuSjFkRUZ1WTNabmRtNUVRWEo1Ulc5RlduSTBOMjltY1hORldXVndWV2QyWVV4WE16VlRiMnRKWldkcVVtaHNXbEp6ZDJaamQyZFFia3RrYkhGWE5rSnVNRXhJV0dwT1ZDdDVPVEoxTjA1dFNHbElhblJIWWpseFNFTXlSaXMxTm1SbmNTdFNiRVpPWW5jMll6TTNTVE5WV20xRE1IVkZNMGd5ZURNemRUTmFVbGhTWVdaTmMwaDBWVk5qTnpKTGJYVlRRMUl5TW1GeU5rYzJUMVE1TmxGcFZGWTJkMlZGYUZsa2JrSlBWbmhNU0cwMWExRnhlV2xXY0hOU09HdHJTa0pGUjBvdlIwdFhVR2h2ZURSTFVWQjNWV0poU2tSSk5FNUJjMEZWTDNwTFpIcHpWRk5rZVhVeVpUVTJSblZPWTNvM01FdDBTRGxsT1dsaFdUWXlNa1I0VGtsWU5YWXJMMVZQWjI1WFFWYzNLMmwxWmpGU1IybG5ZV0kzYlhwUU9HTTBTMHRVVWpOMWNsRXlieTlaTUVJeU5XUm1ZbFl4YWpOeWRraG5OblJ6VVdwdFkwTnVTWGxvV1hreFFUUjBTSGhVTmxoRlluSnNLM1owV21sM2JuaEdiMWxqVkV4V09Gb3ZieTlSTVZaT04xSnJiREowYURBeWNWSmljVEl6VTI1QlJrNXdkVzR6YlVwWFlXSjJSRXQ1WjA5TGRDdEJSak4wVEdvMGEwVlpMMWRqT0dwdGFsRkpWVkZaUm5abmNtZEhOSE5XY1VadE9IcDJNRnAwWWxsbU5IaENZMkZEZERSdmFXNXlkREo2UWtzdlNXTk5aMlJYUmpKbVdFTlRORTFrTTBaRFRIUjJWaTh2WWxKRk0wUndVa3d3Vm1reE1FbG1URzlNY0hJeVFqbFpSR2g2ZEZrcmFTODRja2t2TTJnd2VVRjZOV0ZNWlZoeGJETlVVM1I2VDNGc00yZzJjbXhrVjNsVGNEWTRRbVJQVkdwMWFVRkxTU3RxYUV4MmVHTXJOWEJuTUhwVmFsQldRa1ZRWVhRMVZqUjVZMWxSZW5OTGVHOWlVbmhCU1drMGRsUmlVREVyVldGbU1rVTVUQ3RLYUdoYU1EaENTbnB6Wld0TlFqbHNTM2x6T0VwMk5HRmtRMUp0WjJkakx6QnNjblpLTkZGRGEyUTVka0YxYTJGQlduSlJMMmc1UW5CWldHbHZUemR0YWtWdGMzTlBabEE1V1ZVdlEwUlRjVmhYU1daa2EwNVViMGRJU25CeFNqUldSMlk0UkZwcWVUaFVkVEpKZGxKT2N6Tk9TRU53TkV4bFF6SkVVV3BqVDNoTE5rd3lialZWYkc5ME5reHpVazlVVjFGamJqTTFLMU0zVEU5WGVDODNObWMzWVV3MFZ6SkJPSE5OZFRSYVNTdFlkelZYVFZoMFJrTTJTRlZxZVhaeFNVTlRjVFJ0U1RCYVduUndPR2h1TVhJNVdEQTJXalZRTUhkQmVuWkpVMUJNWVRNM2JrdE9SR3h5VURkRFVsTlBaa2RSYUhaSE5tUjNTbTl3TmxONE0xbzFja2R5VmswM1dVcFpiSGxLUjJKMVdHSmlURzlsU0U5SlVFdERkSFU0TUhSNVdIa3daR1l5WWpVcmNsRmtNRzV2VTFVMFNVa3ZiMFJQV0hGNU9FVktVa1ZWUWpGNlIzUTNUWEZwWkhWck1EUnlLM1JoWTJsWlJqazNWbHBWYWxsTlkyaERXbUowVm1KcVQySlRZV3RaWkdGaVMydE5lRnBWVW1wVVduUjFVakp1ZWpadGFTOXRUa0kwTURJMFR6bFVkR2M1TVUxMlJXRjRlbGh1UmxCdVIxaDVRWGwwVTBWV1ZYZHhXR05QY0dNM01XMWllRXhMUkRWS05WcGlVVE56UTB4aVRVaHBjVlpOYjFWMlZraDRZV0Y2TTJkaVlqQnRTR1JVZUdWSVlWVnNaemR0TTNOaldVOXFiRUYyU0dsSGJuSldXVU12WVRsakwwRlBjMUZFZEdkelMyNWpkWFphY21aM1NYbENXbFJ0VVVGVlRWUkxZMlpwTTFkWVdqQjNjVEJhVEhsUFVEbEVhSEozZVZSdFdIZ3pTMHRTTVVKaVMxSXdTVXRTUm5WTVFuUmxjM0p3YjFoRmFuSnJMMEpvSzFGVVNETndOalZzUjJsUFMxTlNkV0ZyZW1wUFVFUjFhMjh6TW5aUWIzUkRibFoxWmtjeFExWlVVRlF6T1VZemVtTmxhMVpHTm1SRU1rNXJkVEp4TkdsT1owbFFiWGcxYzBGV1NIcFVWbnAxUVhsT05tVldiR2RpUzJOd2FWQmFPRUprUWpWV2FGVkNRbGcwYjFCdGFreFBPWEIyU1ZOSGRERlhlRXBvU1hSNlNEWk9OekI2WlVVM1FVaFZZVGszYURkMllXOXRiMGhWU0UxRVVuSmhXR05sVjBsRVZtMTJXVFYwU0hSSVkwd3hNbUl2WkRsVE5FTlFLelpYY2tFeVpsWXpRVXRCWkZkdlJHbHBiMjFOUTFweU1FOUhkWE5GUkZrd2RIUktaR3BoTTFKaE9HaEVkWGxFYWpKVGJFVmpUWGhhZEVGb1UyaDBTVWd4VEVsa2IyVlRUV2xSVGpOSmIyRjBXVlF2Um05ck1HOVdWelZVWjJaRGVUWnRRVnBSYUVaT2FVZEljM0ZOYlVSS1lYQTVkSHBaZUdWb2RXeEpiR0ZvWTNkcWQyMWpkMUJDVW5GNFNsTkliM2hWWVVWS00zVXJaMFJEUkM5RmRUbDZTVU4wWm5neE16bFJPVEZqYjIxcWVGVmhhMUYyWlRKcVIxQmtXV05QWm5kdWMwWTNhM1JNTlZCTVJWQlBSMDlNVlRsNU5YbG5kbWxpZEhoM056RnZVbmRxUW5wbldtOVpaMmRqZWk4MFVtOWxNMk5ETkN0eE1HVnVZVmt2ZEZONFExTktPVVJyYm1OclYxRXZPWE5MWkhZeldrSnhiMlIwUldGUWIzSkxlall3UzFWVk5qY3JZMGRPYkhvMmJrRmhPSFpIUnpKRlRqRkhhamt6TTAwNGJqSm1jMDlEU1RaVVowd3ZNalF6T1ZOemFXMHpVa3BGTW1RMGJEUlVlbkZGU2xjellXWmlXRFpRZUVseFQyTlBibXRXYjJkSWVqZEtaR2RqUlVsSE5tbElTREppTkdWelVGZzBXV292VldzNFpEWm9hbHBCUkVSb1JXTkZRVXA0UjJocmRYUkxiblV6WW1jMEsyMXRaRFkzTW1WSGIwZEphbGxzYjJsbVJWSmliM1JuVlRkR0swODVhVXBtTVZKcVJsVTNTbEU0WldaRk5VOWxTMFJLUTAxV1RWRkVXVmx1VGs5bVZtdGlWbUpRVmxaMFN6UkNWSEl6V1ZKbVZtUkRWa1k0YkM5b2NEaFhSVXhqWTBadlVrbHJXVmxQTVhaRlF6UlJlSGhDUVVwaVRERmlZekF2TjJkMmR6VlBhVlJxWW1GTVZEUnVWbmsyUjBwUE1IQmtjMlEzVld0M2IyUkRXazVMTDFWS05sVmFPVXh1TkVweGVXcE1ObWR5TTFGTFlUZ3diRkJYUXpoclR6TlFORE5zT1doamNVWmhaamRtUm5GV2VWb3ZVbkoyYUcxRVdHOVViRmhETjNOMVUwMDBORkZSY1dzek5qSkVUSFZyVGxVcllXaHJUSFJaUVRKUlR6Wm9NRm8yY0N0c2VFSmxObUpNZGpKVU9HeEdkMnBMTHpSVldEZHhORmRDVUhoTVozUmtOWEpsWW5sMU9WQldXR051U1dkVlpVMUZkaXRtVEVOVlNsUndWWGRoVERWMlRGWlVRVEIxZEVKYWEzRnhkazAyUWt0TlQxWXdlak1yYzFaSE1VNUxjeTh5TW0xblpFNXNkWGR1UVZabFZERlpVRlZ4TkZWb1ZuQkVSa1o2UTBwV2RXeFdhR2hJYTJwTWFIaFNkMUZRY214eVpXZHVZUzlGV2xGbFpEVlJUall3U2trdlpUZExRamRoV25CMldrdGlNRk5oZEdZdmVXTkxNM1JIZGpsTmVXZElhRWx6Um00NGVWWTBaR0YwT0ZOcllqVlVja1JYVUdGbWNYZHFVbkp5UWtaeU1GTXpWMEl5VTFORmJEVnliMUJsUTJ3NVVVUkVPV1JwV0UxTWIwVnlRa0pDZDJkeU1pdDNjM0V4VjFSM2RHTk1TazAzUlZRdk1FNTRibEpHU25WcU5HdFNNbEY2T1V4a2JUVldhQ3RtVWsxV2VreE5MMlV2ZW5KQ2JFeFhOU3QyZWxWb1lVb3hiell3ZEZkUmNFRkJRM2xzU0cxWlEzWnRaRTB2UlhObGFuZERORFpUWW5aU2RVRnljVzQxVkZaR2RFVlRNaXREUWpSaWEyWkVUbEZQWTB0U09Ya3hiemRSTTJWTGJHUnRSbVZYYzJvd1NVeDZaV2xOVHpKSVZFNVdZVmxIU21jOVBRLlFpSGNGNl9veXdtdEwxc0MwNEI3dW5YdjE2RXlmcnktQkZlM21lbE9FN0hkSjEzbFhQRDRQLXFNSDAxTHkyUEU0VDh4WnJ0VmtRYTh2cld2cUlSdlpB', '_eventId' -> 'idsubmit', 'idlang' -> '', 'geolocation' -> '']\",\"when\":\"2018-09-07T14:45:38,430+0000\",\"clientIpAddress\":\"172.18.0.1\",\"serverIpAddress\":\"172.18.0.8\",\"application\":\"TARA-INSTANCE-3\"}"}
````

Example - full audit trail of successful ID-Card authentication:
````
{"request":"GET https://tara.dev:443/login", "requestId":"V6XLELRZM4RVF6K4", "sessionId":"smvSJcXB8r0rnBnR5-jePEq4rI7fRN3K6mT-VA_pbaw=", "message":"{\"action\":\"AUTHENTICATION_EVENT_TRIGGERED\",\"who\":\"audit:unknown\",\"what\":\"[event=success,timestamp=Fri Sep 07 14:47:13 GMT 2018,source=RankedAuthenticationProviderWebflowEventResolver]\",\"when\":\"2018-09-07T14:47:13,486+0000\",\"clientIpAddress\":\"172.18.0.1\",\"serverIpAddress\":\"172.18.0.8\",\"application\":\"TARA-INSTANCE-3\"}"}
{"request":"GET https://tara.dev:443/idcard", "requestId":"OSWL57CE8O3MQOS2", "sessionId":"smvSJcXB8r0rnBnR5-jePEq4rI7fRN3K6mT-VA_pbaw=", "message":"{\"action\":\"CLIENT_CERT_HANDLING_SUCCESS\",\"who\":\"audit:unknown\",\"what\":\"Supplied parameters: map[[empty]]\",\"when\":\"2018-09-07T14:47:27,023+0000\",\"clientIpAddress\":\"172.18.0.1\",\"serverIpAddress\":\"172.18.0.8\",\"application\":\"TARA-INSTANCE-3\"}"}
{"request":"POST https://tara.dev:443/login", "requestId":"7D8CEU4BJX0C8EN2", "sessionId":"smvSJcXB8r0rnBnR5-jePEq4rI7fRN3K6mT-VA_pbaw=", "message":"{\"action\":\"ESTEID_AUTHENTICATION_SUCCESS\",\"who\":\"audit:unknown\",\"what\":\"Supplied parameters: map['service' -> 'https://tara.dev/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.arendus.kit:8451/oauth/response', 'execution' -> 'be28ebbc-04c4-4cad-8821-4e9366a0ff70_ZXlKaGJHY2lPaUpJVXpVeE1pSjkuVVdVdlRtSnpZekZRYXpFek5rSnNNa1ZKT1ZaRWRWRnZWM2RXV1ZSck56bEpOSGR3TjFSV1p6SnNkakp2WnpaU1NrZGtja2hXYzBkUk1HMWpRbEZ5Y1doWE9FNUxiRWx1YzJGa1VFUTVVVVpPVTIxbmVWWnhOMHRoTTNkRksxazVaQzlSUTJsMGVsbzRjbXBrV25SNFNYbGFha1p6UW1OQ01XbFljU3RsVjNwd1IzaFBjbWx0TVU4MVIxVkRhMWxCYTNsRFkxTkhVbWxTVFhGTVprUkhVa1pNUTFkWGEySmxNR0pKT1VFNFRtMWphVzhyTjBkaU9WRk1hbmhQT0RVelNtOVRSbTQ1WnpRemFERnVWazVUVFhOa01XazNTbm8xUnpsd2FtRnNUbFJLZVhWRVpVUjFkV1F3VUhoc1pqQkpTMW93U2xOaGIyNU1Vbmt3ZUdsRloySjZWblJaZFhGbGEyVnVhM05LV0U5dVVGaEZha2h4V1U5NGIzVnBNVGt2VEhCdVoyRnFlREIzV0cwMFMzWkJhMlJMUzBaV1UzQnRRa041V205MmVGZE1OaTlLVVV0a1R6WlROek5QYW1kcWJFdFViVWhtYzFCVGNUQndjMDV5WlRWUlRHNWhPVTVDTkZWdWFqUTBSa3hEYzA1dldtcGtTSFIxT1hOVlJFazRXVTVKWW1kemRVNDRTbXcxVGprM2RGUlVlbWQ0YzFVNVdpOXhVMjF2WVc5dWVHMDJPVm8zVmxCVlR6RkxNM2RWWkVoRVdXVm1TRkZDWkZCalFrMXFOamxuTDFFMVdFUjZTbTFyZDIxUFVtSnZUV2hPTkZaSmVtWkliMVVyVUVaRVR5dFlaR1JyUkV0R2VtZEVhRWxHZVZKaWJIUnhXVThyYjJvM2FsZzNNbFpXTVd0WVEyUmtiRnBLS3poU1RUaHpVRTQyUVVwelJEaHBlRXAyTWs5SlluRXZNR2MzWmpsdWRIWnNTRUZEY2tOdllWaEtkVmRaT1ZKSU5VRmxNV1JoUldkUlJtWnlVbmg2VjI4d1MzbzVTVVI0Ynl0dFFYSnpURVY0YjFCa1RHRmpVa2x5Y1RWc05UWkdiMDEyZUdOMk1DOW1SMjFtY2pKSlNXOVhNblZrYTIxWk5WVmFPVTE2Y2s4MlIwOUZkV292TlV4RU4wTlZNMDFzVW1jelpUbHZNV0Z0WWxkVFVraHJNVVZSWldwMlJ5OVZkVU5ETkdoVVZXdFZhVkpVZG5oWlFWZGhVRUpUWTFOaVRHbFdVMUIwVTJseE0xZDJOR2wyUVRWVmNIRlBNRkp6Wm1ReFJVcG1VMEpHZWtkVlRWUm1SVmRYWkhadGMwSldRV1ZCVkVJNVdFbFZlV1E0WkVKaGJ6ZHJXRlZPTkVocFRWTnZZak52VjI1VWRIRkVSVWRTY1cxR1JVcFZkakpyT0hscVNEQTJTMVZ3VWtoMVJGbHZTVEJrV2tVeE1YSTVjMDlKUlhjNFRVRlpiSFY2WWtkNGNUaExTWEZHVFd0d1JESXlaRVpVVWtWblVDOWxhM0k1Tm1Wc1pHdzBNRTFrZUVKRWRVcHdSVTQ0VUVKR05ISlBZVVpETDBwNFZqbHlTRXBqUTJkRlpFTmhSa28wUzIxdFQxZGtlVVZ1Ym5KNFEyMUZWamxDYjIxbmFXRktNM1kyVGxKMlRFSkVUazVPZVVSalQyaHZkMVF2U2t4TFkybDBlbEZQTUM5NGRXRXhPSFZoZG1Oa1ltVTFSWGc0UXl0WFNITlVWVFZUYVZreWJ6QkRUalJ3Wm5sbFJVcE1jamhqY25kaU9FaEhSbVZVTnl0U09HcHVhR3QwV25OUFZEUnZka2hNUWtWSGFXNWhZMFY1ZVVKb1FteEJlbFkxZVc1eWFHUkNNRmhNYzBoMU4yOVdiRlJ5Y1ZsM05uRndXVlV5VDFsWVZrbHJPVTUyU0ZWcVlqZGtWMU5tUlhFeVdGRjJXakZMZVRoRE5HTXZNa0ZaV2pocVdVVTFkR2N6ZDFKNVUwVmtNMGh6YVV0MmIwMXVjblZxVW5CRmQyVkRWRkUwWkZadVJYQjNVMGMxVkVwVmRqUXdiRlZHWTBOSkwzSXphM0pVVVROclIzSlFaMFp3WlZkaFdYQkpSVEZTZDB4VFpTOXpaRVZQYTFaSldrOU1MMU52Y1UxVmQzWXJjMlkzTlRVMFlXOVZWVk53TVdOaGJEUjBlV1JFV1hZclRVNVBNMEYzTlZocGNWaEZkR3hTV0U1amMzVnRWU3RhYjBsSVZYQXlhMmg1WVVSaldHUTVSVXhsVm1saFUzbHFOMHRaUVRjNGRGQnZiR1pGYm5KdEswOHpNMlpUVWxJdmFqbG9SbWRtWkVWNFV6UnJSRlk1TkV0VWNrTjNjWE12YzNkaFdqSnJaV3BCVlU5NVNrUXpZemt2ZEdOTlRGWjNPVkYyTlZveE5qUllZWGxyYkVVeGJrOVdhRzgyWlV0MmIzSjRkR1pNTDFSdWVWSm1Ta1ZwVG5WS0x6aFBXWE01VFhOUUt5OVRkMWczU2xwMGNsRldaekU1ZWxOdWVXTlFkRkpJUTAxS1RGRnRZa2R4TkROUFdqVldSRFE0V21ad2RtNXRjVVZtVTNwbWEyUkJVMHh2UVc1alNGUjFUMDExVkZCWk9YcDNhREptVjIwNGNtOUhVbTVQV2twNlVuWTNPV1pCS3l0RlNHODJibWwwVVdWa0wxaG5aR1ZNVW1sblVGY3JaRkF3UlRkalUxcHpaRXhwVWxVd2JYSXlkR2RETTNwQmFEUkxhMGcyY1hsbU9FWkVaalpxWVhOc2VVRnlTVzV5WlVjNFRrSm5RakpQZFhsb2RGb3pWaXRuVUdsR01tTjZZMnN2WjFwd00wdFNSRlU1U2pCU1RqVXlURGhaWVZSTU1VOVpkR0pNVDJWMmMwazNaMk12ZEd4dk9HRktlV2R2YjNKalNFMUxlV2xwSzJSVmJscEhZbmRQZVhWRWNFZHhVRlpoYldwVGRXeERRa3RNTUhwWldUUnljM1l6SzFsclJXbE5NMElyVUVsdE4yTjVRMmxTYmtneVRrSjJZV0ZyVld0MU1IVnRia1JEYzBneFdFd3hjMmxUTlRGdEx6TnZUV3hWYlRoS2EycFlLMmR5ZUhjd1ZFazFaRE51Y0dKMFdEZHhPSE4zWmpOdFN6bFdjR3d4TVhveVJUZFlVaXR5UkZKVFZFWXJPRWdyT1ZsUWVpODNiVGxtTmtaSFZFSXlXRkJyVmxWTkx6SjJiblZYVlcxT01VOUJTR3RrT1hoMVZGSXJZbTlxY0hKMlluaGtORVJ5V25WeGF5OTFkbGxFY2t4TWJFTnNWR1ozVXpoWE5IVnpWSFJIZWxZeldUTjVUWFJPTld0cWRFZEVSRkF4TTI1bksycEVRbTFtWkhjeWEzbzBSRFJtZVZCemMzRlpPVEZNVDBKV2NYVlRha2haVGxsdE1TdFRRV2R0Y1U1b2NGSk9hbTlrZEdaS1NuQllVVVpJWTB0TVVYZ3ZhRXBaYTBaSFdIY3pSREZHWW5ab2QwZFhjVXBhVGpOekwyc3djRWRFYlRkbk5qZG9iVlJIY0VOeFVGZE9ZMWxUTlhaNmFVeEVPRVo1Y2tNcmJUQnJhRWg2SzJoRVEzRjBjV3BQWjBoTE1rRXZVWEJtUVZsWWJuRlFZbXMyUzJKWk4yUjFUV3hLZHpsMVFXcHBkV0l6YkRkVlJIRmtkR3BhTVc4MWNuQTNXa3RhVDBGSFVFbHJkVGh0VDNoUE5HMVlUak5YYVhwWldqQkNTM2RFWW1FM0sxQTFUbUk1VUdaVllVRkpaWEJrY0hsRFlqWm9jV2g0Ym5GdWFrTXhURTl1VFRJNVRscG5RMGRGV0dsV1ZFTmxTMEZ4TTNab2JrNXlUSHBTY0dFNVZsSlFSRnBNUjFVeGNVWTJWWEJDTmxkYVRVY3JTRzVKVTFRMVZEbERaM0JpU1U5MFdqWXhaVXBvT0dKVGVWWnBlQzg1V1dkcVJFazFXblJ1TkV0cVNqRXdiakpaUlN0dE0wOU5ObEEyTmpkM056aDNaWEExVDBKRFREbFllbkE0ZFZwVE4wNDFhMkZHUjBKU1JEWnJXVTB3VDNvME1tMVJVR2M1YVROUU9IVXdNbUo1Y1dsMFJ6ZzRSV2RFTVdaRVUzWnZlR2c0YTJOMGFFb3JhMUEyTDJWSFRucEpla2xQT1VoTk1qRkhkbUYzZVhFdlNEZFlWWFpMWWxNMVVGVjZRbXhYVTBjNGJqWklRMVpLVVVwSmJWTm1OblowY3pJNVR5OXBUbmh0V1RscEwxTk1hMU01Wm5wNllYTTFUa2xtVnpWb1lUbE1kbFV6ZWxKdWIyVlJjM05xTTJwRU0wcHRUbVY0Y1ZSWmNVWjZhalF5TWpFclFtOUJOeXRJZVhsS1IycFpUM1YxUlVOek5Vb3plbTVUYlRkaFRqTk1SM3BDY25rdlIwUkphR05tZGtWb1dsaG9Tamt3WkhwbU5DdFJkREJIVHpad2JtSlBNa0pKTXpOcFdEZGxNRVFyS3pSdGNIRTNTSGxSV1cxSWQzSkZSREJVYWxRd1VVeHZTbEJ3VkRjdk1FMXlaekpQVjJRMFlVdDZSQ3RTTTJkeWF6QkRPSGRxYkVKUWFYWlVObGRsUlhOd2JtMUxaa3RaY21oT1ZISnZXVmd3YUVOdWVteFZNazVGYzI5aVkwNVBVa3BTVEc1TU9ETllSVGRVYVV4V01qSlVSRlEyV0ZGSmJXSnNVbmsxYmpoTGEwcG1abTFvU2pNdlFqRkJlbU55ZFZjdmJUQkhaRXhOZVVOUmNqTkdPVlZGTUhoVlRTdEdZV1p0UWxNNVN6UTRSblJKWVZNNVRYcFViMWx0T0RWU09FRnBhbEYxVVhKUGVIUktiSEUyVkU0eldFVXhhRmhJYzNSaWJqQlBTVmM0TDIxWGRIRkxlV05tWWtoVk4zRm5aakZ5V1Zwd2VIVlBOM1k1TDJvMmVuRkNMMkZWZGs0M1VIRnhZalV3VlRoM1FqSm1WMVpsU0ZCQmMyeFRiRzUwWTJFeWVTdEdVa3hpTlU0eVZXRkNka1F5TVVsWlVrZGpUSEZGTlVkc1JVSkpSRkU1YWsxc1FrbGtiRmcyVW1OVFUzZFdjbEV3V0VKdE9GWlNNR3BNYUdsVlFVNW5NbU5FY0V4aVIxaE1OVVJyU1VWb2NFUXhLelUzYWtWWlJDOU5SVFZMVkhWeVdGZFJPRUpvTDJkUE5qSXJlamRyTDFvMWFVNUxUMnBaU0ROdVZrZDJWa2RYVnpGT1RUaEVjRTV6VFVWWE1URjJZWFJsZURaNFJFOWxTR3QzTUhWVE9EaFRVV0VyV1ZKeVpYTkRieTkyV1hJd1EzZFVPVmwwV0hRNFIwMVlia1ZEV1RkU2N6WXdjUzluYzFaR1JWbGpVM0F6V2xBNVIybEdWbTB5TmtwclJXODJZVUZvVFM5M1ZUSk9SazlIYmxoMksxZHdkMFZWUTBWd1ZEQnBUMGs0VEU5TlRHZHNjRzlpTkhjMk1rMVNVSGxPYkM5NUt5dFhUV3h4VTFGcU5rRnhZamMwU0N0UWRtNHpSVlpSVEdWV1N6Y3haSEZUTjFJemRFWktjblJpWjBKamFsRm1XbFpHYzJ3NFZYRlJRMGRpUlZKM2MxWm5VSGd6ZUZoT04zSkNlRFEzZVZKM05HNW5UVE5hVUZneGVsQktWMEZNTmpNd2NVbzFhSFp3YzNOSlMzSndkelZQUm1scFJ5OHJWaXQyYVd0S2NXSldORVUxVUVReGMxVTRaVk5TWXpRMFkza3pjbUkwTWpFemEwTktlbWxRYW5WdVNtVTBOVGxqWW1oRU1VRmpjVnBUTm5CcVJXTk1SV1JVYjB4MlQySXhVMVk0V0c1Uk5EQjZTRzB5VHpoYWIxUnFTVzV0TW5jOVBRLms1SU5OTGNJX2RwMW1mTlhhRlBfSWFCeXRscXBtQVkzTGpxR2xPX1hGa2NnY2xpcERMWlJUbTlQWTVaT3pXMzlDQWdXV2YzMUI1akFab1lFOWRBQWRn', '_eventId' -> 'idsubmit', 'idlang' -> '', 'geolocation' -> '']\",\"when\":\"2018-09-07T14:47:27,441+0000\",\"clientIpAddress\":\"172.18.0.1\",\"serverIpAddress\":\"172.18.0.8\",\"application\":\"TARA-INSTANCE-3\"}"}
{"request":"POST https://tara.dev:443/login", "requestId":"7D8CEU4BJX0C8EN2", "sessionId":"smvSJcXB8r0rnBnR5-jePEq4rI7fRN3K6mT-VA_pbaw=", "message":"{\"action\":\"AUTHENTICATION_SUCCESS\",\"who\":\"EE47101010033\",\"what\":\"Supplied credentials: [TaraCredential{type=IDCard, principalCode='EE47101010033', firstName='MARI-LIIS', lastName='M?NNIK', mobileNumber='null', country='null', dateOfBirth='null', levelOfAssurance=null, banklinkType=null}]\",\"when\":\"2018-09-07T14:47:27,481+0000\",\"clientIpAddress\":\"172.18.0.1\",\"serverIpAddress\":\"172.18.0.8\",\"application\":\"TARA-INSTANCE-3\"}"}
{"request":"POST https://tara.dev:443/login", "requestId":"7D8CEU4BJX0C8EN2", "sessionId":"smvSJcXB8r0rnBnR5-jePEq4rI7fRN3K6mT-VA_pbaw=", "message":"{\"action\":\"TICKET_GRANTING_TICKET_CREATED\",\"who\":\"EE47101010033\",\"what\":\"TGT-**********************************************sPr9Pv6Br1-tara\",\"when\":\"2018-09-07T14:47:27,549+0000\",\"clientIpAddress\":\"172.18.0.1\",\"serverIpAddress\":\"172.18.0.8\",\"application\":\"TARA-INSTANCE-3\"}"}
{"request":"POST https://tara.dev:443/login", "requestId":"7D8CEU4BJX0C8EN2", "sessionId":"smvSJcXB8r0rnBnR5-jePEq4rI7fRN3K6mT-VA_pbaw=", "message":"{\"action\":\"SERVICE_TICKET_CREATED\",\"who\":\"EE47101010033\",\"what\":\"ST-1-nKrANQNh9dmDnefpx7nV-tara for https://tara.dev/oauth2.0/callbackAuthorize?client_name=CasOAuthClient&client_id=openIdDemo&redirect_uri=https://tara-client.arendus.kit:8451/oauth/response\",\"when\":\"2018-09-07T14:47:27,572+0000\",\"clientIpAddress\":\"172.18.0.1\",\"serverIpAddress\":\"172.18.0.8\",\"application\":\"TARA-INSTANCE-3\"}"}
{"request":"GET https://tara.dev:443/p3/serviceValidate", "requestId":"278NR8DA1C17HE73", "sessionId":"Is5Lsv0QNZV7WlfebWf3GkyXigpSx7paB4JGVb4XyQQ=", "message":"{\"action\":\"SERVICE_TICKET_VALIDATED\",\"who\":\"EE47101010033\",\"what\":\"ST-1-nKrANQNh9dmDnefpx7nV-tara\",\"when\":\"2018-09-07T14:47:27,665+0000\",\"clientIpAddress\":\"172.18.0.8\",\"serverIpAddress\":\"172.18.0.8\",\"application\":\"TARA-INSTANCE-3\"}"}
{"request":"GET https://tara.dev:443/oidc/authorize", "requestId":"ZA989GJI2F4LWQQT", "sessionId":"smvSJcXB8r0rnBnR5-jePEq4rI7fRN3K6mT-VA_pbaw=", "message":"{\"action\":\"OAUTH_CODE_CREATED\",\"who\":\"audit:unknown\",\"what\":\"OC-***************************zTcnSEzgZd\",\"when\":\"2018-09-07T14:47:27,784+0000\",\"clientIpAddress\":\"172.18.0.1\",\"serverIpAddress\":\"172.18.0.8\",\"application\":\"TARA-INSTANCE-3\"}"}
{"request":"POST https://tara.dev:443/oidc/accessToken", "requestId":"4H8PI1FOM1RG5TN8", "sessionId":"2_Y_MoI0BoOItwoXrlf_WiR0Fye5plIotyEnl0NSnXc=", "message":"{\"action\":\"ACCESS_TOKEN_REQUEST_HANDLING_SUCCESS\",\"who\":\"audit:unknown\",\"what\":\"Supplied parameters: map['grant_type' -> array<String>['authorization_code'], 'code' -> array<String>['OC-***************************zTcnSEzgZd'], 'redirect_uri' -> array<String>['https://tara-client.arendus.kit:8451/oauth/response']]; Generated id-token: eyJhbGciOiJSUzI1NiIsImtpZCI6IjY1YzYxZDY5LWIyODEtNGZlYS1iNDM1LTc4NzQwMWEyMjRiZiJ9.eyJqdGkiOiI4ZmIyMWM5ZS0zYTkxLTQzM2MtYTNjMy0wNDg1YWVlMTZiYzIiLCJpc3MiOiJodHRwczovL2tvb2dlbG1vb2dlbC5uZXQvb2lkYyIsImF1ZCI6Im9wZW5JZERlbW8iLCJleHAiOjE1MzYzNjA0NDcsImlhdCI6MTUzNjMzMTY0NywibmJmIjoxNTM2MzMxMzQ3LCJzdWIiOiJFRTQ3MTAxMDEwMDMzIiwicHJvZmlsZV9hdHRyaWJ1dGVzIjp7ImRhdGVfb2ZfYmlydGgiOiIxOTcxLTAxLTAxIiwiZmFtaWx5X25hbWUiOiJNw4ROTklLIiwiZ2l2ZW5fbmFtZSI6Ik1BUkktTElJUyJ9LCJhbXIiOlsiaWRjYXJkIl0sInN0YXRlIjoiYWJjZGVmZ2hpamtsbW5vcCIsIm5vbmNlIjoicXJzdHV2d3h5emFiY2RlZiIsImF0X2hhc2giOiJEUWxYcmZSVkdxL2x0eXJRTTF4aEpRPT0ifQ.T_uKOF4th9GjJsXIkjUJ6kJazv4sR89VeUN0bVerX6n37b_YKTPsxKmucOEwQzeapaoK8dv9tVnUlG4B9_NCjagWSypn2I5ZbwmuyP1F2xpAXfIcK58a8Mqf5CZq-Y8ja-xGcqxf2ybyqIq0IW7PGW9hu1Ec5A9o-Yp779gV1A86XgWBR52-wIz95L1th9FPuwJ73_UOKtDjQ7NzmHNPVEL15vujrq429MDf-vduVcbRAnjnKjnNCcu2yiUl4n4ZGkgNGD15c7uUXEalOw6GGuRqEVTxskyxXibPVPWmjGCB6eZ21ppVMFdfhaOeCv6kIjCZWAn0kba1e78VCikJvA\",\"when\":\"2018-09-07T14:47:27,898+0000\",\"clientIpAddress\":\"172.18.0.9\",\"serverIpAddress\":\"172.18.0.8\",\"application\":\"TARA-INSTANCE-3\"}"}
````

<a name="tara_syslog"></a>
### 1.3 Logging to remote syslog server

The default logging configuration contains example appenders for forwarding log events to a remote syslog server that accepts log messages over TLS-TCP using [RFC-5424 format](https://tools.ietf.org/html/rfc5424.html#section-6.2.1).

The syslog message format has been set up so that the facility code is always `local1(17)` and syslog message priority in case of an log4j2 ERROR event is `error(3)` and `notice(5)` in all other cases (WARN, DEBUG, INFO, etc).

Note that the syslog loggers are not enabled by default. Remote syslog configuration needs to be explicitly enabled and TLS key and syslog server cert configured in `log4j2.xml` file.


<a name="audit_events"></a>
### 1.4 TARA Audit trail events

The following is a complete list of TARA specific audit events:

| **Event** | **Description** |
| :---------------- | :---------- |
| `CLIENT_CERT_HANDLING_SUCCESS` | Initial ID-Card certificate header verification was successful. |
| `CLIENT_CERT_HANDLING_FAILED` | Initial ID-Card certificate header verification has failed. |
| `ESTEID_AUTHENTICATION_SUCCESS` | A successful ID-Card authentication procedure has been completed. |
| `ESTEID_AUTHENTICATION_FAILED` | ID-Card authentication has failed. |
| `MID_AUTHENTICATION_INIT_SUCCESS` | Estonian Mobile-ID init request successful. |
| `MID_AUTHENTICATION_INIT_FAILED` | Estonian Mobile-ID init request failed. |
| `MID_AUTHENTICATION_STATUS_POLL_SUCCESS` | Estonian Mobile-ID status check request was successful. |
| `MID_AUTHENTICATION_STATUS_POLL_FAILED` | Estonian Mobile-ID status check request failed. |
| `MID_AUTHENTICATION_STATUS_POLL_CANCEL_SUCCESS` | Estonian Mobile-ID status check was cancelled by the user.  |
| `MID_AUTHENTICATION_STATUS_POLL_CANCEL_FAILED` | Estonian Mobile-ID status check cancellation by the user has failed. |
| `SMARTID_AUTHENTICATION_INIT_SUCCESS` | Smart-ID authentication init request was successful |
| `SMARTID_AUTHENTICATION_INIT_FAILED` | Smart-ID authentication init request has failed |
| `SMARTID_AUTHENTICATION_STATUS_POLL_SUCCESS` | Smart-ID authentication status polling request was successful. |
| `SMARTID_AUTHENTICATION_STATUS_POLL_FAILED` | Smart-ID authentication status polling request has failed. |
| `SMARTID_AUTHENTICATION_STATUS_POLL_CANCEL_SUCCESS` | Smart-ID authentication status polling was successfully canceled by the user. |
| `SMARTID_AUTHENTICATION_STATUS_POLL_CANCEL_FAILED` | Smart-ID authentication status polling cancellation by the user has failed.  | 
| `EIDAS_AUTHENTICATION_INIT_SUCCESS` | eIDAS authentication was successfully initiated. |
| `EIDAS_AUTHENTICATION_INIT_FAILED` | eIDAS authentication failed to init. |
| `EIDAS_AUTHENTICATION_CALLBACK_SUCCESS` | eIDAS authentication successful. |
| `EIDAS_AUTHENTICATION_CALLBACK_FAILED` | eIDAS authentication failed (the other party replied with an error). |
| `BANKLINK_AUTHENTICATION_INIT_SUCCESS` | Banklink authentication request successfully sent. |
| `BANKLINK_AUTHENTICATION_INIT_FAILED` | Error while creating the banklink request. |
| `BANKLINK_AUTHENTICATION_CALLBACK_SUCCESS` | Bank's response was successfully received and validated. |
| `BANKLINK_AUTHENTICATION_CALLBACK_FAILED` | Error occurred while processing the bank's response. |
| `OAUTH_CODE_CREATED` | Authentication code was successfully created. |
| `OAUTH_CODE_NOT_CREATED` | Authentication code creation failed. |
| `ACCESS_TOKEN_REQUEST_HANDLING_SUCCESS` | Request was successfully processed and an access token was sent as a response. |
| `ACCESS_TOKEN_REQUEST_HANDLING_FAILED` | An error occurred while processing the request or sending the response. |
| `USER_INFO_DATA_CREATED`| User profile data for UserInfo endpoint response was successfully created. |
| `USER_INFO_DATA_NOT_CREATED`| User profile data creation for UserInfo endpoint response has failed. |

NB! See additional list of CAS related events [here](https://apereo.github.io/cas/5.3.x/installation/Audits.html#audit-events)


<a name="tara_stat_log"></a>
### 1.5 Logging to Tara-Stat

TARA can also send statistics as JSON formatted event stream to the [Tara-Stat service](https://e-gov.github.io/TARA-Stat/Dokumentatsioon).

Note that the Tara-Stat logger is not enabled by default. Tara-Stat needs to be explicitly configured in `application.properties` and `log4j2.xml` file (see [Tara-Stat configuration](Configuration.md#tara_stat) for further details)


<a name="configuration_parameters"></a>
## 2. TARA specific configuration parameters
--------------------

The configuration of the TARA service is managed through a central configuration properties file - `application.properties`. In addition to Apereo CAS configuration properties described [here](https://apereo.github.io/cas/5.3.x/installation/Configuration-Properties.html) the `application.properties` can also include properties for TARA specific features. The following document describes the custom configuration properties available in TARA service.


<a name="id_card"></a>
### 2.1 ID-card authentication

Table 2.1.1 - Enabling ID-card authentication feature in TARA

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `id-card.enabled` | N | Feature toggle for authentication with ID-card in TARA. Enables this feature to be loaded if set to `true`, otherwise ignores all other ID-card related configuration. Defaults to `false`, if not specified. |

Table 2.1.2 - Enabling ID-card certificate validation

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `id-card.ocsp-enabled` | N | Enables ID-card certificate validation if set to `true`, otherwise ignores all other ocsp related configuration. Defaults to `true`, if not specified. |

Table 2.1.3 - Configuring ID-card truststore 

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `id-card.truststore` | Y | Path to the truststore that holds list of OCSP responder certificates and ID-card issuer certificates. For example: `classpath:id-card-truststore.p12`, when the file is to be accessed from the classpath or `file:/etc/cas/id-card-truststore.p12` when the file is referenced in the local filesystem.  |
| `id-card.truststore-type` | N | Truststore type. Defaults to `PKCS12` |
| `id-card.truststore-pass` | Y | Truststore password |

Table 2.1.4 - Explicit configuration of the OCSP service(s) 

TARA allows multiple sets of OCSP configurations to be defined by using the `id-card.ocsp[{index}]` notation. 

Each OCSP configuration can contain the following set of properties: 


| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `id-card.ocsp[{index}].issuer-cn` | Y | A comma separated list of supported certificate issuer CN-s (CN in the certificate) that this OCSP supports. <br/><br/>Note that the certificate referenced by CN must be present in the truststore (`id-card.truststore`) |
| `id-card.ocsp[{index}].url` | Y | The HTTP URL of the OCSP service. |
| `id-card.ocsp[{index}].responder-certificate-cn` | N | Explicit OCSP response signing certificate CN. If not provided, OCSP reponse signer certificate is expected to be issued from the same chain as user-certificate. <br/><br/>Note that responder certificate extended key usage must have the OCSP signing (`1.3.6.1.5.5.7.3.9`) value. |
| `id-card.ocsp[{index}].nonce-disabled` | N | Boolean value, that determines whether the nonce extension usage is disabled. Defaults to `false` if not specified. |
| `id-card.ocsp[{index}].accepted-clock-skew-in-seconds` | N | Maximum accepted time difference in seconds between OCSP provider and TARA-Server. Defaults to `2`, if not specified. |
| `id-card.ocsp[{index}].response-lifetime-inseconds` | N | Maximum accepted age of an OCSP response in seconds. Defaults to `900` if not specified. |
| `id-card.ocsp[{index}].connect-timeout-in-milliseconds` | N | Connection timout in milliseconds. Defaults to `3000`, if not specified. |
| `id-card.ocsp[{index}].read-timeout-in-milliseconds` | N | Connection read timeout in milliseconds. Defaults to `3000` if not specified. |

NB! A default configuration is used when a user certificate is encountered by a trusted issuer, that has no matching OCSP configuration by the issuer's CN and the user certificate contains the AIA OCSP URL (the configuration will use the default values of the properties listed in Table 4)


Example 1: using SK AIA OCSP only (a non-commercial, best-effort service):

````
id-card.enabled = true
id-card.ocsp-enabled=true

id-card.truststore=classpath:/id-card/idcard-truststore-test.p12
id-card.truststore-type=PKCS12
id-card.truststore-pass=changeit

id-card.ocsp[0].issuer-cn=TEST of ESTEID-SK 2011
id-card.ocsp[0].url=http://aia.sk.ee/esteid2011
id-card.ocsp[0].nonce-disabled=true

id-card.ocsp[1].issuer-cn=TEST of ESTEID-SK 2015
id-card.ocsp[1].url=http://aia.sk.ee/esteid2015
id-card.ocsp[1].nonce-disabled=true

id-card.ocsp[2].issuer-cn=ESTEID2018
id-card.ocsp[2].url=http://aia.sk.ee/esteid2018
id-card.ocsp[2].nonce-disabled=false
````

Example 2:  using SK's commercial OCSP only (with subscription only):

````
id-card.enabled = true
id-card.ocsp-enabled=true

id-card.truststore=classpath:/id-card/idcard-truststore-test.p12
id-card.truststore-type=PKCS12
id-card.truststore-pass=changeit

id-card.ocsp[0].issuer-cn=ESTEID-SK 2011, ESTEID-SK 2015, ESTEID2018
id-card.ocsp[0].url=http://ocsp.sk.ee/
id-card.ocsp[0].responder-certificate-cn=SK OCSP RESPONDER 2011
````


Table 2.1.5 - Configuring fallback OCSP service(s)

When the primary OCSP service is not available (ie returns other than HTTP 200 status code, an invalid response Content-Type or the connection times out) a fallback OCSP connection(s) can be configured to query for the certificate status.

In case of multiple fallback configurations per issuer, the execution order is determined by the order of definition in the configuration. 
 
The following properties can be used to configure a fallback OCSP service:
  

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `id-card.fallback-ocsp[{index}].issuer-cn` | Y | A comma separated list of certificate issuer CN's. Determines the issuer(s) this fallback configuration will be applied to. <br/><br/>Note that the certificate by CN must be present in the truststore (`id-card.truststore`) |
| `id-card.fallback-ocsp[{index}].url` | Y | HTTP URL of the OCSP service. |
| `id-card.fallback-ocsp[{index}].responder-certificate-cn` | N | Explicit OCSP response signing certificate CN. If not provided, OCSP reponse signer certificate is expected to be issued from the same chain as user-certificate. |
| `id-card.fallback-ocsp[{index}].nonce-disabled` | N | Boolean value, that determines whether the nonce extension usage is disabled. Defaults to `false` if not specified. |
| `id-card.fallback-ocsp[{index}].accepted-clock-skew-in-seconds` | N | Maximum accepted time difference in seconds between OCSP provider and TARA-Server. Defaults to `2`, if not specified. |
| `id-card.fallback-ocsp[{index}].response-lifetime-inseconds` | N | Maximum accepted age of an OCSP response in seconds. Defaults to `900` if not specified. |
| `id-card.fallback-ocsp[{index}].connect-timeout-in-milliseconds` | N | Connection timout in milliseconds. Defaults to `3000`, if not specified. |
| `id-card.fallback-ocsp[{index}].read-timeout-in-milliseconds` | N | Connection read timeout in milliseconds. Defaults to `3000` if not specified. |


Example: AIA OCSP by default using a static backup OCSP 

````
id-card.enabled = true
id-card.ocsp-enabled=true

id-card.truststore=classpath:/id-card/idcard-truststore-test.p12
id-card.truststore-type=PKCS12
id-card.truststore-pass=changeit

# configure AIA ocsp
id-card.ocsp[0].issuer-cn=ESTEID-SK 2011
id-card.ocsp[0].url=http://aia.sk.ee/esteid2011
id-card.ocsp[0].nonce-disabled=true

id-card.ocsp[1].issuer-cn=ESTEID-SK 2015
id-card.ocsp[1].url=http://aia.sk.ee/esteid2015
id-card.ocsp[1].nonce-disabled=true

id-card.ocsp[2].issuer-cn=ESTEID2018
id-card.ocsp[2].url=http://aia.sk.ee/esteid2018
id-card.ocsp[2].nonce-disabled=false

# use as fallback
id-card.fallback-ocsp[0].issuer-cn=ESTEID-SK 2011, ESTEID-SK 2015, ESTEID2018
id-card.fallback-ocsp[0].url=http://ocsp.sk.ee/
id-card.fallback-ocsp[0].responder-certificate-cn=SK OCSP RESPONDER 2011
````

<a name="mobile_id"></a>
### 2.2 Mobile-ID authentication

Table 2.2.1 - Enabling mobile-ID authentication feature in TARA

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `mobile-id.enabled` | N | Feature toggle for authentication with mobile-ID in TARA. Enables this feature to be loaded if set to `true`, otherwise ignores all other mobile-ID related configuration. Defaults to `false`, if not specified. |

Table 2.2.2 - Configuring Mobile-ID authentication ([MID-REST](https://github.com/SK-EID/MID))

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `mobile-id.language` | N | Language for user dialog in mobile phone. 3-letters capitalized acronyms are used. Possible values: <ul><li>`EST`</li><li>`ENG`</li><li>`RUS`</li><li>`LIT`</li></ul> Defaults to `EST`, if not specified.<br>For more information, see `language` query parameter in [MidRest Specification](https://github.com/SK-EID/MID#32-initiating-signing-and-authentication). |
| `mobile-id.message-to-display` | Y | Text displayed in addition to ServiceName and before asking authentication PIN. Maximum length is 40 bytes. In case of Latin letters, this means also a 40 character long text, but Cyrillic characters may be encoded by two bytes and you will not be able to send more than 20 symbols.<br>For more information, see `displayText` query parameter in [MidRest Specification](https://github.com/SK-EID/MID#32-initiating-signing-and-authentication). |
| `mobile-id.message-to-display-encoding` | N | Specifies which characters and how many can be used in `message-to-display`. Possible values are `GSM7` and `UCS2`, Defaults to `GSM7`. For more information, see `displayTextFormat` query parameter in [MidRest Specification](https://github.com/SK-EID/MID#32-initiating-signing-and-authentication). |
| `mobile-id.host-url` | Y | HTTP URL of the MID-REST service operator. |
| `mobile-id.relying-party-name` | Y | Name of the relying party according to the contract between mobile-ID service provider and the relying party. Displayed together with displayText and Verification Code on cellphone screen before End User can insert PIN. |
| `mobile-id.relying-party-uuid` | Y | UUID value of the relying party according to the contract between mobile-ID service provider and the relying party. |
| `mobile-id.authentication-hash-type` | N | Type of the randomly generated hash from which verification code is calculated. Possible values are `SHA256`, `SHA384` and `SHA512`. Defaults to `SHA256`. |
| `mobile-id.session-status-socket-open-duration` | N | Maximum time in milliseconds the server is allowed to wait before returning a response. Defaults to (and rounded up, if below) `1000`, if not specified. For more information, see parameter `timeoutMs` in [MidRestLongPolling Specification](https://github.com/SK-EID/MID#334-long-polling) |
| `mobile-id.timeout-between-session-status-queries` | N | Timeout in milliseconds between consecutive session status queries. Defaults to `5000`, if not specified. |
| `mobile-id.read-timeout` | N | Maximum total time in milliseconds to be spent on status queries during a session. Defaults to `30000`, if not specified. <br>This value should not be smaller than sum of `mobile-id.session-status-socket-open-duration` and 1500ms (approximate additional time to transfer the request and response over the network)! |
| `mobile-id.connection-timeout` | N | Maximum time spent in milliseconds on waiting for connection with mobile-ID service provider. Defaults to `5000`, if not specified. |

Example:

````
mobile-id.enabled=true
mobile-id.language=EST
mobile-id.message-to-display=Näita siin
mobile-id.message-to-display-encoding=GSM7
mobile-id.host-url=https://tsp.demo.sk.ee/mid-api
mobile-id.relying-party-name=DEMO
mobile-id.relying-party-uuid=00000000-0000-0000-0000-000000000000
mobile-id.authentication-hash-type=SHA256
mobile-id.session-status-socket-open-duration=1000
mobile-id.timeout-between-session-status-queries=3000
mobile-id.read-timeout=30000
mobile-id.connection-timeout=5000
````


<a name="eidas"></a>
### 2.3 eIDAS authentication

Table 2.3.1 - Enabling eIDAS authentication feature in TARA

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `eidas.enabled` | N | Feature toggle for authentication with eIDAS in TARA. Enables this feature to be loaded if set to `true`, otherwise ignores all other eIDAS related configuration. Defaults to `false`, if not specified. |

Table 2.3.2 - Configuring eIDAS authentication

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `eidas.service-url` | Y | HTTP base URL of the eIDAS-client microservice. |
| `eidas.heartbeat-url` | N | HTTP URL of the eIDAS-client microservice heartbeat endpoint. Affects TARA [heartbeat endpoint](#heartbeat). |
| `eidas.available-countries` | Y | A comma separated list of ISO 3166-1 alpha-2 country codes that determine which countries are displayed on the login page. Also for each country code a 'eidas:country:x' (where x is the country code in lowercase) entry is added to the 'scopes_supported' field, which is communicated through TARA-Server metadata.  |
| `eidas.client-certificate-enabled` | N | Feature toggle for using client certificate when making requests to authentication endpoints at `eidas.service-url`. Enables this feature if set to `true`, otherwise ignores all other client certificate related configuration. Defaults to `false`, if not specified. |
| `eidas.connection-pool.max-total` | N | Maximum number of allowed total open connections to `eidas.service-url` endpoint. Defaults to `20`, if not specified. |
| `eidas.connection-pool.max-per-route` | N | Maximum number of allowed concurrent connections per route to `eidas.service-url` endpoint. Defaults to `2`, if not specified. |

Table 2.3.3 - Configuring client certificate for requests to authentication endpoints at `eidas.service-url`

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `eidas.client-certificate-keystore` | Y | Path to the keystore that holds client certificate and private key. For example: `classpath:eidasClientKeystore.p12`, when the file is to be accessed from the classpath or `file:/etc/cas/eidasClientKeystore.p12` when the file is referenced in the local filesystem.  |
| `eidas.client-certificate-keystore-type` | N | Keystore type. Defaults to `PKCS12` |
| `eidas.client-certificate-keystore-pass` | Y | Keystore password. |

Example:

````
eidas.enabled=true
eidas.service-url=https://<eidas-client-host:port>
eidas.heartbeat-url=https://<eidas-client-host:port>/heartbeat
eidas.available-countries=EE,LT,LV,FI,NO,IT,IE

eidas.connection-pool.max-total=100
eidas.connection-pool.max-per-route=5

eidas.client-certificate-enabled=true
eidas.client-certificate-keystore=classpath:/eidas-client/clientCertificateKeystore.p12
eidas.client-certificate-keystore-type=PKCS12
eidas.client-certificate-keystore-pass=changeit
````


<a name="banklink"></a>
### 2.4 Estonian banklinks

Table 2.4.1 - Enabling banklink feature in TARA


| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `banklinks.enabled` | N | Feature toggle for banklink functionality in TARA. Enables banklinks feature to be loaded when set to `true`, otherwise ignores all other banklink related configuration. Defaults to `false`, if not specified. |

Table 2.4.2 - Generic banklink properties

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `banklinks.available-banks` | Y | A comma separated list of bank codes that determine which bank link(s) are displayed on the login page. Supported values in the list are: <ul><li>`seb`</li><li>`luminor`</li><li>`coop`</li><li>`swedbank`</li><li>`lhv`</li><li>`danske`</ul> For example:`seb,lhv,luminor`. <br>Note that adding a bank to this list, requires further bank specific property configuration (see Table 11 for details) |
| `banklinks.keystore` | Y | Path to the keystore that holds bank keys. For example: `classpath:banklinkKeystore.p12`, when the file is to be accessed from the classpath or `file:/etc/cas/banklinkKeystore.p12` when the file is referenced in the local filesystem.  |
| `banklinks.keystore-type` | N | Keystore type. Defaults to `PKCS12` |
| `banklinks.keystore-pass` | Y | Keystore password. |
| `banklinks.return-url` | Y | HTTP URL for accepting the bank authentication response. Must reference the publicly available TARA `/login` url. |

Table 2.4.3 - Bank specific properties


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
### 2.5 Estonian Smart-ID

Table 2.5.1 - Enabling Smart-ID authentication feature in TARA

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `smart-id.enabled` | N | Feature toggle for authentication with Smart-ID in TARA. Enables this feature to be loaded if set to `true`, otherwise ignores all other Smart-ID related configuration. Defaults to `false`, if not specified. |

Table 2.5.2 - Other Smart-ID configuration properties (if Smart-ID is enabled)

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `smart-id.host-url` | Y | HTTP URL of the Smart-ID service. |
| `smart-id.relying-party-name` | Y | Name of the relying party according to the contract between Smart-ID service provider and the relying party. This field is case insensitive. |
| `smart-id.relying-party-uuid` | Y | UUID value of the relying party according to the contract between Smart-ID service provider and the relying party. |
| `smart-id.authentication-hash-type` | N | Type of the authentication hash that is used to generate the control code of an authentication request. Supported values are: <ul><li>`SHA256`</li><li>`SHA384`</li><li>`SHA512`</li></ul> Defaults to `SHA512`, if not specified. |
| `smart-id.authentication-consent-dialog-display-text` | Y | Description of the authentication request. Displayed on the consent dialog shown on the end user's device. |
| `smart-id.session-status-socket-open-duration` | N | Maximum duration in milliseconds a session status query is kept alive. Defaults to `1000`, if not specified. Smaller than `1000` numbers are rounded to `1000`, because it is the minimum that is used by Smart-ID service. |
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
### 2.6 Heartbeat endpoint

TARA heartbeat endpoint is a Spring Boot Actuator endpoint and thus is configured as described [here](https://docs.spring.io/spring-boot/docs/1.5.3.RELEASE/reference/html/production-ready-endpoints.html), while also taking into consideration CAS specific configuration properties as described [here](https://apereo.github.io/cas/5.3.x/installation/Configuration-Properties.html#spring-boot-endpoints).

Table 2.6.1 - Configuring heartbeat endpoint in TARA

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `endpoints.heartbeat.*` | N | Spring Boot specific actuator configuration. |
| `endpoints.heartbeat.timeout` | N | Maximum time to wait on status requests made to systems that TARA is depending on, in seconds. Defaults to 3 seconds. |

Table 2.6.2 - Heartbeat endpoints on systems TARA is depending on

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `eidas.heartbeat-url` | N | HTTP URL of the eIDAS-client microservice heartbeat endpoint. If set, the eIDAS-client status affects the overall reported status of TARA-server. |

Example configuration with **heartbeat** endpoint enabled, accessible without authentication and from all IP-addresses, and configure eIDAS-client **heartbeat** URL:

````
endpoints.heartbeat.enabled=true
endpoints.heartbeat.sensitive=false

# Allow access from all IP-addresses
cas.adminPagesSecurity.ip=.+

# Configure eIDAS-client heartbeat url
eidas.heartbeat-url=https://<eidas-client-host:port>/heartbeat
````


<a name="security_csp"></a>
### 2.7 Content Security Policy

Table 2.7.1 - Enabling TARA-specific `Content-Security-Policy` headers in responses from TARA server

| Property        | Mandatory | Description |
| :-------------- | :-------- | :-----------|
| `security.csp.enabled` | N | Toggle for explicit Content Security Policy. Enables this feature to be loaded if set to `true`, otherwise ignores all other CSP related configuration. Defaults to `false`, if not specified. |

Optional CSP directive-specific parameters are based on [Content Security Policy Level 3 directives](https://www.w3.org/TR/CSP/#csp-directives).
Optional CSP directive-specific parameters can be specified in the following form

````
security.csp.<directive-name> = <optional-value>
````

The values of optional CSP directive-specific parameters must be specified exactly the same way as the values of those directives appear in a valid `Content-Security-Policy` header according to the [CSP specification](https://www.w3.org/TR/CSP/#framework-directives).

Example (using currently recommended CSP configuration for TARA):

````
# Enable Content Security Policy
security.csp.enabled=true

# CSP fetch directives
# Fallback for unspecified fetch directives
security.csp.default-src='none'
# Allow fetching fonts from the origin
security.csp.font-src='self'
# Allow fetching images from the origin
security.csp.img-src='self'
# Allow fetching scripts from the origin
security.csp.script-src='self'
# Allow fetching css from the origin
security.csp.style-src='self'
# Allow AJAX for /idcard endpoint
security.csp.connect-src='self'

# Other directives
# Restrict any URLs in HTML <base> element
security.csp.base-uri='none'
# Disallow any parents from embedding this page
security.csp.frame-ancestors='none'
# Block all mixed content (a CSP directive with no value)
security.csp.block-all-mixed-content=
````


<a name="tara_stat"></a>
### 2.8 TARA-Stat interfacing

The TARA-Stat service (see https://e-gov.github.io/TARA-Stat/Dokumentatsioon for details) can be used as one of the receivers of TARA statistics.

Table 2.8.1 - Enabling TARA-Stat statistics logging

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `statistics.tara-stat.enabled` | N | Feature toggle for logging statistics info to the TARA-Stat service. Enables this feature to be loaded if set to `true`, otherwise disables it. Defaults to `false`, if not specified. |

NB! When enabled, additional logger and appender must be configured to send the statistics to the external service (in `log4j2.xml`).

Example log4j2 configuration for sending statistics over TCP in syslog format:

````
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
   <Appenders>
      ... additional appenders ...
      <Syslog name="taraStatServiceAppender" host="tara-stat.dev" port="5001" protocol="TCP" charset="UTF-8" newLine="true" facility="AUTH" >
         <SSL>
            <KeyStore   location="/path/to/tarastat-client-keystore.jks"      password="changeit"/>
            <TrustStore location="/path/to/tarastat-client-truststore.jks"    password="changeit"/>
         </SSL>
      </Syslog>
   </Appenders>

   <Loggers>

      ... additional loggers ...
      <AsyncLogger name="ee.ria.sso.statistics.TaraStatHandler" level="info" additivity="false">
         <AppenderRef ref="taraStatServiceAppender"/>
      </AsyncLogger>
   </Loggers>
</Configuration>
````


<a name="test_environment_warning"></a>
### 2.9 Test environment warning message

Table 2.9.1 - Configuring TARA login page to show a warning message about it being run against test services

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `env.test.message` | N | Warning message to show. No warning displayed if not set. |

Example:

````
env.test.message=Tegemist on testkeskkonnaga ja autentimiseks vajalik info on <a href="https://e-gov.github.io/TARA-Doku/Testimine#testimine-testnumbrite-ja-id-kaardiga">TARA dokumentatsioonis</a>!
````


<a name="audit_logging"></a>
### 2.10 Audit logging

Table 2.10.1 - Relevant CAS parameters for TARA audit log

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `cas.audit.appCode` | N | The tara instance name to be displayed in the audit event. Display's `CAS` by default, if not specified. |

Example:

````
cas.audit.appCode=TARA-INSTANCE-1
````

NB! Note that audit logging can be further customized by CAS configuration parameters (see [CAS documentation](https://apereo.github.io/cas/5.3.x/installation/Configuration-Properties.html#audits)).


<a name="oidc_optional_endpoints"></a>
### 2.11 OpenID Connect optional endpoints

Table 2.11.1 - Relevant parameters for enabling/disabling additional OpenID Connect endpoints in CAS

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `oidc.dynamic-client-registration.enabled` | N | Enables/disables the CAS built-in /oidc/registration endpoint and displays/hides the related information at the /oidc/.well-known/openid-configuration. Defaults to `false`, if not specified. |
| `oidc.profile-endpoint.enabled` | N | Enables/disables the CAS built-in /oidc/profile endpoint and displays/hides the related information at the /oidc/.well-known/openid-configuration. Defaults to `true`, if not specified. |
| `oidc.revocation-endpoint.enabled` | N | Enables/disables the CAS built-in /oidc/revocation endpoint and displays/hides the related information at the /oidc/.well-known/openid-configuration. Defaults to `false`, if not specified. |
| `oidc.introspection-endpoint.enabled` | N | Enables/disables the CAS built-in /oidc/introspection endpoint and displays/hides the related information at the /oidc/.well-known/openid-configuration. Defaults to `false`, if not specified. |

Example:

````
oidc.dynamic-client-registration.enabled=true
oidc.profile-endpoint.enabled=true
oidc.revocation-endpoint.enabled=true
oidc.introspection-endpoint.enabled=true
````

<a name="oidc_client_secret"></a>
### 2.12 Client secret handling

Table 2.12.1 - Parameters regarding the handling of client secrets

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `tara.digestAlgorithm` | N | Algorithm used to hash client secret on the fly, before comparing it to registered client secret. One of the values specified by the [Java Cryptography Architecture Standard Algorithm Name Documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest). Defaults to `SHA-256` if not specified. |

Example:

````
tara.digestAlgorithm=SHA-256
````
  
<a name="oidc_force_reauthentication"></a>
### 2.13 Forcing re-authentication
Force re-authentication

Table 2.13.1 - Parameters for users to reauthenticate 

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `oidc.authorize.force-auth-renewal.enabled` | N | A boolean flag that always forces /oidc/authorize user to reauthenticate. Defaults to `true`, if not specified.  |

Example:

````
oidc.authorize.force-auth-renewal.enabled=false
````

<a name="default_auth_methods"></a>
### 2.14 Default list of authentication methods
Change the list of authentication methods displayed to the user on the Login page by default.

Table 2.14.1 - Parameters used to specify the list of default authentication methods 

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `tara.default-authentication-methods` | N | A comma separated list of authentication methods that will be displayed to the user by default (if the OpenID Connect client does not specify authentication method by scope explicitly). Allowed values: `idcard`, `mobileid`, `banklink`, `eidas`, `smartid` . Defaults to `idcard, mid`, if not specified.  |

Example:

````
tara.default-authentication-methods=idcard, mobileid, eidas, banklink, smartid
````    

<a name="eidas_auth_methods_loa"></a>
### 2.15 Assigning eIDAS level of assurance to domestic authentication methods

Explicitly specifying the level of assurance for domestic authentication methods allows TARA clients to filter the domestic authentication methods displayed to the user by acr_values parameter. In addition, assigning a level of assurance for domestic authenticatiom method also adds the `acr` claim to the id-token issued by TARA.  

Table 2.15.1 - Parameters to specify the level of assurance for domestic authentication methods. 

| Property        | Mandatory | Description |
| :---------------- | :---------- | :----------------|
| `tara.authentication-methods-loa-map.<auth method>` | N | <p>The `<auth method>` in the configuration parameter template can have values: `idcard`, `mobileid`, `banklink`, `smartid`.</p> <p>Valid values for a parameter are: `low`, `substantial`, `high` </p>. |

Example:

````
tara.authentication-methods-loa-map.idcard=high
tara.authentication-methods-loa-map.mobileid=high
tara.authentication-methods-loa-map.banklink=low
tara.authentication-methods-loa-map.smartid=substantial
````

<a name="tara_truststore"></a>
## 3. TARA truststore
------------------

In order to make TARA more secure, a dedicated truststore should be used instead of the default Java VM truststore. This can be achieved with Java command-line options (either directly or via environment variable `JAVA_OPTS`).

Example:

````
-Djavax.net.ssl.trustStore=/truststore_location/tara.truststore -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=jks
````

The previous example assumes a truststore file `tara.truststore`, located at `/truststore_location/`, having `changeit` as its password and being in the JKS format.


### 3.1 MID REST trusted certificates

In order to be able to use Mobile-ID authentication in TARA, a relevant MID-REST endpoint TLS certificates must be added to TARA truststore.

#### Live environment

TARA is configured against the live environment of MID-REST if `mobile-id.service-url` in `application.properties` is set (see [Mobile-ID authentication](#mobile_id)).
The TLS certificate of the live environment of DigiDocService is available at the Estonian Certification Centre [certificate repository](https://www.sk.ee/en/repository/certs/) under the name of `mid.sk.ee`.

An example of adding DigiDocService TLS certificate to TARA truststore:
````
keytool -importcert -keystore tara.truststore -storepass changeit -file mid_sk_ee.PEM.cer -alias midrest -noprompt
````

#### Demo environment

TARA is configured against the demo environment of DigiDocService if `mobile-id.service-url` in `application.properties` is set to `https://tsp.demo.sk.ee` (see [Mobile-ID authentication](#mobile_id)).

An example of obtaining DigiDocService TLS certificate with an `openssl` command:
````
openssl s_client -connect tsp.demo.sk.ee:443 -showcerts
````
The relevant certificate is displayed at depth 0 of the certificate chain in the command output.
After copying the certificate into a file, it can be imported into TARA truststore the same way as shown for the live certificate.


### 3.2 Smart-ID

In order to be able to use Smart-ID authentication in TARA, a relevant Smart-ID service endpoint certificate must be added to TARA truststore.

#### Live environment

TARA is configured against the live environment of Smart-ID service if `smart-id.host-url` in `application.properties` is set to `https://rp-api.smart-id.com/v1/` (see [Estonian Smart-ID](#smart-id)).
The TLS certificate of the live environment of Smart-ID service is available at the Estonian Certification Centre [certificate repository](https://www.sk.ee/en/repository/certs/) under the name of `rp-api.smart-id.com`.

An example of adding Smart-ID service TLS certificate to TARA truststore:
````
keytool -importcert -keystore tara.truststore -storepass changeit -file rp-api.smart-id.com.pem.cer -alias rpapismartidcom -noprompt
````

#### Demo environment

TARA is configured against the demo environment of Smart-ID service if `smart-id.host-url` in `application.properties` is set to `https://sid.demo.sk.ee/smart-id-rp/v1/` (see [Estonian Smart-ID](#smart-id)).

An example of obtaining Smart-ID service TLS certificate with an `openssl` command:
````
openssl s_client -connect sid.demo.sk.ee:443 -showcerts
````
The relevant certificate is displayed at depth 0 of the certificate chain in the command output.
After copying the certificate into a file, it can be imported into TARA truststore the same way as shown for the live certificate.

<a name="cas_properties"></a>
## 4. CAS properties
------------------

<a name="cas_service_name"></a>
### 4.1 Showing service's name
On Mobile-ID and Smart-ID authentication pages, showing the service name is possible, so users can see the service they're entering more clearly.

In order to show service's name when on Mobile-ID or Smart-ID authentication pages, the service name must be defined in CAS Management.

In ````CAS Management -> Properties```` tab, set the property name as ````service.name```` and value as the service's name.

Example:

|     Name     |          Value          |   
|:------------:|:-----------------------:|
| service.name | Eesti riigi infoportaal |

If no service name is defined, Mobile-ID and Smart-ID pages will be displayed without the service's name.


<a name="cas_service_name_translation"></a>
### 4.2 Translating service's name

In addition to showing the service's name, translating the service name to English and Russian languages is possible.

Navigate to  ````CAS Management -> Properties```` tab.

Translate to English: set the property name as ````service.name.en````.

Translate to Russian: set the property name as ````service.name.ru````.

Set the service value(s) as needed.

If translated names aren't defined, Mobile-ID and Smart-ID pages will be displayed with the default service's name (if defined).

Example:

|       Name      |                   Value                      |   
|:-------------- :|:--------------------------------------------:|
| service.name.en | Estonian government information portal       |
| service.name.ru | Информационный портал эстонского государства |

<a name="cas_service_short_name"></a>
### 4.3 Showing service's short name
During Mobile-ID and Smart-ID authentication (where user enters PIN code), it's possible to show the service name in short form.

Example: Full name - ````Eesti riigi infoportaal````, short name - ````eesti.ee````

In order to show service's short name when authenticating with Mobile-ID or Smart-ID, the short name must be defined in CAS Management.

In ````CAS Management -> Properties```` tab, set the property name as ````service.shortName```` and value as the service's short name.

Example:

|        Name       |   Value  |   
|:-----------------:|:--------:|
| service.shortName | eesti.ee |

If no short name is defined, Mobile-ID and Smart-ID pages will be displayed without the service's short name.

<a name="cas_service_short_name_translation"></a>
### 4.4 Translating service's short name

In addition to showing the service's short name, it's possible to translate it to English and Russian languages.

Navigate to  ````CAS Management -> Properties```` tab.

Translate to English: set the property name as ````service.shortName.en````.

Translate to Russian: set the property name as ````service.shortName.ru````.

Set the service value(s) as needed.

If translated short names aren't defined, Mobile-ID and Smart-ID pages will be displayed with the default service's short name (if defined).

Example:

|        Name          |     Value      |   
|:--------------------:|:--------------:|
| service.shortName.en | englishService |
| service.shortName.ru | russianService |