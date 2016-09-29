#!/bin/bash

CLIENT_CERT="/home/pspirek/sslclient/pavel_curl.pem"

echo "--- conf-start 1"
POST_DATA='{ "dns-server:input": {"name": "Edit 1"} }'
URL="https://127.0.0.1:8443/restconf/operations/dns-server:conf-start"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST -d "$POST_DATA" "$URL" 2>/dev/null

echo "--- POST new zone"
POST_DATA='{"zone": {"domain": "newzone.cz"}}'
URL="https://127.0.0.1:8443/restconf/data/dns-server:dns-server/zones"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST -d "$POST_DATA" "$URL" 2>/dev/null

echo "--- conf-commit"
URL="https://127.0.0.1:8443/restconf/operations/dns-server:conf-commit"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST "$URL" 2>/dev/null

sleep 2

echo "--- zone conf-start 1"
POST_DATA='{ "dns-server:input": {"name": "Zone data edit 1"} }'
URL="https://127.0.0.1:8443/restconf/operations/dns-server:conf-start"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST -d "$POST_DATA" "$URL" 2>/dev/null

echo "--- POST new zone SOA"
POST_DATA='{"zone": {"name": "newzone.cz", "class": "IN", "default-ttl": 3611, "SOA": {"mname": "dns1.newzone.cz","rname": "hostmaster.newzone.cz","serial": 20160622,"refresh": 200,"retry": 300,"expire": 400,"minimum": 500}}}'
URL="https://127.0.0.1:8443/restconf/data/dns-zones:zone-data"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST -d "$POST_DATA" "$URL" 2>/dev/null

echo "--- POST new zone A"
POST_DATA='{"rrset": {"owner": "sub", "type": "iana-dns-parameters:A", "rdata": [{"id": "1", "A": { "address": "192.168.100.100"}}]}}'
URL="https://127.0.0.1:8443/restconf/data/dns-zones:zone-data/zone=newzone.cz,IN"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST -d "$POST_DATA" "$URL" 2>/dev/null

echo "--- POST new zone A 2"
POST_DATA='{"rdata": {"id": "2", "A": { "address": "192.168.100.101"}}}'
URL="https://127.0.0.1:8443/restconf/data/dns-zones:zone-data/zone=newzone.cz,IN/rrset=sub,iana-dns-parameters:A"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST -d "$POST_DATA" "$URL" 2>/dev/null

echo "--- conf-list"
URL="https://127.0.0.1:8443/restconf/operations/dns-server:conf-list"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST "$URL" 2>/dev/null

echo "--- conf-commit"
URL="https://127.0.0.1:8443/restconf/operations/dns-server:conf-commit"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST "$URL" 2>/dev/null

echo "--- GET zones"
URL="https://127.0.0.1:8443/restconf/data/dns-zones:zone-data/zone=newzone.cz,IN"
curl -v --http2 -k --cert-type PEM -E $CLIENT_CERT -X GET "$URL" 2>/dev/null
