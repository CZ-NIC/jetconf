#!/bin/sh
if [ "$1" = "" ]; then
	echo "Usage:" $0 "out_filename_prefix"
	exit 1
fi

echo "\n1. Generating private key:"
openssl genrsa -out $1.key 2048

echo "\n2. Generating CSR:"
openssl req -new -key $1.key -out $1.req

echo "\n3. Signing CSR with test CA's key:"
openssl x509 -req -in $1.req -CA ca.pem -CAkey ca.key -days 365 -out $1.pem

echo "\n4. Creating combined $1_curl.pem file containing both certificate and key (for curl etc.):"
cat $1.pem > $1_curl.pem
cat $1.key >> $1_curl.pem

