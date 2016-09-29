#!/bin/bash

CLIENT_CERT="/home/pspirek/sslclient/pavel_curl.pem"

echo "--- zone conf-start 1"
POST_DATA='{ "dns-server:input": {"name": "Zone data edit 1"} }'
URL="https://127.0.0.1:8443/restconf/operations/dns-server:conf-start"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST -d "$POST_DATA" "$URL" 2>/dev/null

#echo "--- DEL new zone A"
#URL="https://127.0.0.1:8443/restconf/data/dns-zones:zone-data/zone=newzone.cz,IN/rrset=sub,iana-dns-parameters:A"
#curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X DELETE "$URL" 2>/dev/null

echo "--- DEL new zone A"
URL="https://127.0.0.1:8443/restconf/data/dns-zones:zone-data/zone=newzone.cz,IN/rrset=sub,iana-dns-parameters:A/rdata=1"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X DELETE "$URL" 2>/dev/null

echo "--- zone conf-commit"
URL="https://127.0.0.1:8443/restconf/operations/dns-server:conf-commit"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST "$URL" 2>/dev/null

echo "--- GET new zone"
URL="https://127.0.0.1:8443/restconf/data/dns-zones:zone-data/zone=newzone.cz,IN"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X GET "$URL" 2>/dev/null
