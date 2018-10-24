#!/bin/bash
if [ $# -ne 2 ] && [ $# -ne 3 ]; then
    echo "Usage:"
    echo "    $0 <out_file_suffix> <domain/ip>"
    echo "or:"
    echo "    $0 <out_file_suffix> <domain/ip> <server_key>"
    echo "I.e. $0 example example.com will create file server_example.crt"
    echo "with new private key."
    exit 1
fi

# Generate server private key if not passed from the command line
if [ $# -eq 2 ]; then
    KEY_FILE=server_$1.key
    echo -e "\nGenerating new private key:"
    openssl genrsa -out $KEY_FILE 2048
else
    KEY_FILE=$3
fi

CSR_CNF_FILE=/tmp/srv.csr.cnf
V3EXT_FILE=/tmp/srv.v3ext

# Prepare temporary configuration file
cat << EOF > $CSR_CNF_FILE
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
CN = $2
EOF

# Prepare temporary v3-extensions file
cat << EOF > $V3EXT_FILE
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
EOF

# Test if certificate is being issued for domain or IP and set a correct SAN
if [[ $2 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "IP.1 = $2" >> $V3EXT_FILE
else
  echo "DNS.1 = $2" >> $V3EXT_FILE
fi

echo -e "\n1. Generating CSR:"
openssl req -new -key $KEY_FILE -out server_$1.csr -sha256 -config $CSR_CNF_FILE

echo -e "\n2. Signing CSR with test CA's key:"
openssl x509 -req -in server_$1.csr -CAcreateserial -CA ca.pem -CAkey ca.key -days 3650 -sha256 -extfile $V3EXT_FILE -out server_$1.crt

rm -f server_$1.csr $CSR_CNF_FILE $V3EXT_FILE
echo -e "\nDone"
