#!/bin/bash

if [[ -f $(which mbedtls_gen_key) ]]; then
	GEN_KEY="/usr/bin/mbedtls_gen_key"
	GEN_CERT="/usr/bin/mbedtls_cert_write"
else
	GEN_KEY="/usr/bin/gen_key"
	GEN_CERT="/usr/bin/cert_write"
fi

KEY_PEM="keys/test-proxy-key.pem"
CERT_PEM="keys/test-proxy-cert.pem"

${GEN_KEY} type=ec ec_curve=secp256r1 format=pem filename=${KEY_PEM}

${GEN_CERT} issuer_name="CN=goldy.local, O=Dummy Ltd, C=US" \
	selfsign=1 \
	issuer_key=${KEY_PEM} \
	output_file=${CERT_PEM}
