#!/bin/sh
if [ "$1" = "" ]; then
	echo "Usage:" $0 "out_filename_prefix"
	exit 1
fi

echo -e "\n1. Generating private key:"
openssl genrsa -out $1.key 2048

echo -e "\n2. Generating CSR:"
openssl req -new -key $1.key -out $1.req -subj "/CN=Test/emailAddress=$1@mail.cz"

echo -e "\n3. Signing CSR with test CA's key:"
openssl x509 -req -in $1.req -CA ca.pem -CAkey ca.key -days 3650 -out $1.pem
rm $1.req

echo -e "\n4. Creating $1_curl.pem (concaterated certificate and key for curl etc.):"
cat $1.pem > $1_curl.pem
cat $1.key >> $1_curl.pem

echo -e "\n5. Creating .pfx for web browsers (password: $1):"
openssl pkcs12 -export -out $1.pfx -inkey $1.key -in $1.pem -password pass:$1

echo -e "\nDone"
