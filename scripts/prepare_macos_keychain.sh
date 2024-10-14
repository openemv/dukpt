#!/bin/bash

# This script is inspired by these guides:
# - https://docs.github.com/en/actions/deployment/deploying-xcode-applications/installing-an-apple-certificate-on-macos-runners-for-xcode-development
# - https://localazy.com/blog/how-to-automatically-sign-macos-apps-using-github-actions
# - https://federicoterzi.com/blog/automatic-code-signing-and-notarization-for-macos-apps-using-github-actions/
# - https://github.com/lando/code-sign-action/

# This script assumes that these environment variables are provided:
# - RUNNER_TEMP (temporary directory provided by Github Actions runner)
# - OPENEMV_MACOS_CERT_BASE64
# - OPENEMV_MACOS_CERT_PWD
# - KEYCHAIN_PASSWORD

# TODO: remove
set -x

# Temporary paths
OPENEMV_MACOS_CERT_PATH=$RUNNER_TEMP/certificate.p12
KEYCHAIN_PATH=$RUNNER_TEMP/app-signing.keychain-db

# Create temporary keychain
security create-keychain -p "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH
security default-keychain -s $KEYCHAIN_PATH
security unlock-keychain -p "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH
security set-keychain-settings -ut 21600 $KEYCHAIN_PATH

# Decode and import signing certificate
#echo -n "$OPENEMV_MACOS_CERT_BASE64" | base64 --decode --input - --output $OPENEMV_MACOS_CERT_PATH
#echo -n "$OPENEMV_MACOS_CERT_BASE64" | base64 -d -i - -o $OPENEMV_MACOS_CERT_PATH
#echo -n "$OPENEMV_MACOS_CERT_BASE64" | base64 -d -o $OPENEMV_MACOS_CERT_PATH
echo -n "$OPENEMV_MACOS_CERT_BASE64" | base64 --decode > $OPENEMV_MACOS_CERT_PATH
#openssl pkcs12 -in $OPENEMV_MACOS_CERT_PATH -info -noout -password "$OPENEMV_MACOS_CERT_PWD"
openssl pkcs12 -in $OPENEMV_MACOS_CERT_PATH -info -noout -passin ${OPENEMV_MACOS_CERT_PWD}
#security import $OPENEMV_MACOS_CERT_PATH -P "$OPENEMV_MACOS_CERT_PWD" -A -t cert -f pkcs12 -k $KEYCHAIN_PATH
security import $OPENEMV_MACOS_CERT_PATH -P "$OPENEMV_MACOS_CERT_PWD" -k $KEYCHAIN_PATH -T /usr/bin/codesign -T /usr/bin/productsign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH
#security list-keychains -d user -s $KEYCHAIN_PATH
security find-identity -v -p codesigning
security find-identity -v -p codesigning $KEYCHAIN_PATH
security find-identity $KEYCHAIN_PATH

# Allow codesign application to use signing key
#security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH

# TODO: remove
which codesign

# Cleanup
rm $OPENEMV_MACOS_CERT_PATH
