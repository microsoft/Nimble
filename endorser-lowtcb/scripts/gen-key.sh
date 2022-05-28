#!/bin/bash

openssl genrsa -out private.pem -3 3072
openssl rsa -in private.pem -pubout -out public.pem

set -e
set -u

HOST=endorser3.eastus.cloudapp.azure.com
SUBJ_ROOT="/C=US/ST=Washington/O=EMQ/CN=TMCS"
SUBJ_CLIENT="/C=US/ST=Washington/O=EMQ/CN=TMCSClient"
SUBJ_SERVER="/C=US/ST=Washington/O=EMQ/CN=TMCSServer"
DAYS=3650

openssl genrsa -out root-ca.key 4096

openssl req \
    509 \
    -nodes \
    -new \
    -key root-ca.key \
    -out root-cacert-server.pem \
    -subj $SUBJ_ROOT \
    -sha256 \
    -days $DAYS

openssl req \
    -x509 \
    -nodes \
    -new \
    -key root-ca.key \
    -out root-cacert-client.pem \
    -subj $SUBJ_ROOT \
    -sha256 \
    -days $DAYS

(cat /etc/ssl/openssl.cnf; printf "[SAN]\nsubjectAltName=DNS:$HOST") > openssl.cnf

openssl genrsa -out client.key 2048

openssl req \
    -new \
    -key client.key \
    -out client-cert.csr \
    -subj $SUBJ_CLIENT \
    -reqexts SAN \
    -extensions SAN \
    -config openssl.cnf

openssl x509 \
    -req \
    -in client-cert.csr \
    -out client-cert.pem \
    -CA root-cacert-client.pem \
    -CAkey root-ca.key \
    -CAcreateserial \
    -CAserial $HOST-CA.serial \
    -extensions SAN \
    -extfile openssl.cnf \
    -sha256 \
    -days $DAYS

openssl genrsa -out server.key 2048

openssl req \
    -new \
    -key server.key \
    -out server-cert.csr\
    -subj $SUBJ_SERVER \
    -reqexts SAN \
    -extensions SAN \
    -config openssl.cnf

openssl x509 \
    -req \
    -in server-cert.csr \
    -out server-cert.pem \
    -CA root-cacert-server.pem \
    -CAkey root-ca.key \
    -CAcreateserial \
    -CAserial $HOST-CA.serial \
    -extensions SAN \
    -extfile openssl.cnf \
    -sha256 \
    -days $DAYS
