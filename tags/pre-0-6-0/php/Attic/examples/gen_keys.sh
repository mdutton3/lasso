#!/bin/sh
# 
# Generate OpenSSL certificats for PHP IdP and SP Lasso samples
#

SP=sample-sp
SP_CFG=$SP/sp_openssl.cnf
SP_PRV=$SP/private-key-raw_sp1.pem
SP_CRT=$SP/certificate_sp1.pem
SP_PUB=$SP/public-key_sp1.pem

IDP=sample-idp
IDP_CFG=$IDP/idp_openssl.cnf
IDP_PRV=$IDP/private-key-raw_idp1.pem
IDP_CRT=$IDP/certificate_idp1.pem
IDP_PUB=$IDP/public-key_idp1.pem

openssl req -config $SP_CFG -out $SP_CRT -keyout $SP_PRV -x509 -nodes -newkey -batch
openssl x509 -in $SP_CRT -noout -pubkey > $SP_PUB

openssl req -config $IDP_CFG -out $IDP_CRT -keyout $IDP_PRV -x509 -nodes -newkey -batch
openssl x509 -in $IDP_CRT -noout -pubkey > $IDP_PUB

cp -p $IDP_CRT $IDP_PUB $SP
cp -p $SP_CRT $SP_PUB $IDP
