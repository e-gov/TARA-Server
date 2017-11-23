CAS Overlay Template
============================

Generic CAS WAR overlay to exercise the latest versions of CAS. This overlay could be freely used as a starting template for local CAS war overlays. The CAS services management overlay is available [here](https://github.com/apereo/cas-services-management-overlay).

# Versions

```xml
<cas.version>5.1.x</cas.version>
```

# Requirements
* JDK 1.8+

# Configuration

The `etc` directory contains the configuration files and directories that need to be copied to `/etc/cas/config`.

# Build

To see what commands are available to the build script, run:

```bash
./build.sh help
```

To package the final web application, run:

```bash
./build.sh package -Pprod
```

To update `SNAPSHOT` versions run:

```bash
./build.sh package -U -Pprod
```

When `Maven` is installed in current environment different profiles can be used for building like:

```bash
mvn clean package -P<profile>
```

where profile can be `dev`, `test` and `prod`

# Deployment

- Create a keystore file `thekeystore` under `/etc/cas`. Use the password `changeit` for both the keystore and the key/certificate entries.
- Ensure the keystore is loaded up with keys and certificates of the server.

On a successful deployment via the following methods, CAS will be available at:

* `http://cas.server.name:8080/cas`
* `https://cas.server.name:8443/cas`

## App Server Selection
There is an app.server property in the pom.xml that can be used to select a spring boot application server.
It defaults to "-tomcat" but "-jetty" and "-undertow" are supported. 
It can also be set to an empty value (nothing) if you want to deploy CAS to an external application server of your choice and you don't want the spring boot libraries included. 

```xml
<app.server>-tomcat<app.server>
```

## Windows Build
If you are building on windows, try build.cmd instead of build.sh. Arguments are similar but for usage, run:  

```
build.cmd help
```

## External

Deploy resultant `target/cas.war`  to a servlet container of choice.

## Development
When building WAR with development mode please execute the following command

```
mvn clean package -Pdev
```

When running standalone CAS server instance you can define `cas.log.dir` and `cas.log.level` system parameters to control logging output
