#!/bin/bash

function help() {
	echo "Usage: build.sh [clean|package|gencert]"
	echo "	clean: Clean Maven build directory"
	echo "	package: Clean and build CAS war, also call copy"
	echo "	gencert: Create keystore with SSL certificate in location where CAS looks by default"
}

function clean() {
	./mvnw clean "$@"
}

function package() {
	./mvnw clean package -T 5 "$@"
	copy
}

function gencert() {
	which keytool
	if [[ $? -ne 0 ]] ; then
	    echo Error: Java JDK \'keytool\' is not installed or is not in the path
	    exit 1
	fi
	# override DNAME and CERT_SUBJ_ALT_NAMES before calling or use dummy values
	DNAME="${DNAME:-CN=cas.example.org,OU=Example,OU=Org,C=US}"
	CERT_SUBJ_ALT_NAMES="${CERT_SUBJ_ALT_NAMES:-dns:example.org,dns:localhost,ip:127.0.0.1}"
	echo "Generating keystore for CAS with DN ${DNAME}"
	keytool -genkeypair -alias cas -keyalg RSA -keypass changeit -storepass changeit -keystore /etc/cas/thekeystore -dname ${DNAME} -ext SAN=${CERT_SUBJ_ALT_NAMES}
	keytool -exportcert -alias cas -storepass changeit -keystore /etc/cas/thekeystore -file /etc/cas/cas.cer
}

if [ $# -eq 0 ]; then
    echo -e "No commands provided. Defaulting to [run]\n"
    run
    exit 0
fi


case "$1" in
"clean")
	shift
    clean "$@"
    ;;   
"package")
	shift
    package "$@"
    ;;
"gencert")
    gencert "$@"
    ;;
*)
    help
    ;;
esac

