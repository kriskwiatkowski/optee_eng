#!/bin/sh

# Re-creates certificates for server and client VPN
OPENSSL_BIN=openssl
OPENSSL_REHASH_BIN=c_rehash
TMP_DIR=certs
set -x

create_openvpn_pki()
{
  # Create CA key and certificate
  ${OPENSSL_BIN} ecparam \
    -name secp256r1 \
    -genkey \
    -out ${TMP_DIR}/ca.key || exit;
  ${OPENSSL_BIN} req \
    -new \
    -config openssl.cnf \
    -x509 \
    -extensions v3_ca \
    -key ${TMP_DIR}/ca.key \
    -out ${TMP_DIR}/ca.cert \
    -days 9999 \
    -subj "/O=Among Bytes, vpn.testlab.com/CN=Root Cert G1" \
    -batch || exit;

  # Create server certificate
  ${OPENSSL_BIN} ecparam \
    -name secp256r1 \
    -genkey \
    -out ${TMP_DIR}/server.key || exit;
  ${OPENSSL_BIN} req \
    -new \
    -config openssl.cnf \
    -key ${TMP_DIR}/server.key \
    -out ${TMP_DIR}/server.csr \
    -subj "/O=Cert Testing ORG/CN=vpn.testlab.com" \
    -batch || exit;
  ${OPENSSL_BIN} x509 \
    -extfile openssl.cnf \
    -extensions server_cert \
    -req  \
    -CA ${TMP_DIR}/ca.cert \
    -CAkey ${TMP_DIR}/ca.key \
    -CAcreateserial \
    -in ${TMP_DIR}/server.csr \
    -out ${TMP_DIR}/server.cert \
    -days 9999 || exit;
  OPENSSL=${OPENSSL_BIN} ${OPENSSL_REHASH_BIN} ${TMP_DIR}
  ${OPENSSL_BIN} verify \
    -CApath ${TMP_DIR} \
    ${TMP_DIR}/server.cert || exit;

  # Create client certificate
  ${OPENSSL_BIN} ecparam \
    -name secp256r1 \
    -genkey \
    -out ${TMP_DIR}/client.key || exit;
  ${OPENSSL_BIN} req \
    -new \
    -config openssl.cnf \
    -key ${TMP_DIR}/client.key \
    -out ${TMP_DIR}/client.csr \
    -subj "/O=Cert Testing ORG/CN=Client Cert" \
    -batch || exit;
  ${OPENSSL_BIN} x509 \
    -extfile openssl.cnf \
    -extensions client_cert \
    -req  \
    -CA ${TMP_DIR}/ca.cert \
    -CAkey ${TMP_DIR}/ca.key \
    -CAcreateserial \
    -in ${TMP_DIR}/client.csr \
    -out ${TMP_DIR}/client.cert \
    -days 9999 || exit;
  ${OPENSSL_BIN} verify \
    -CApath ${TMP_DIR}/ \
    ${TMP_DIR}/client.cert || exit;
}

rm -rf ${TMP_DIR}
mkdir -p ${TMP_DIR}
create_openvpn_pki
