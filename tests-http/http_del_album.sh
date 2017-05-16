#!/bin/bash

CLIENT_CERT="/home/pspirek/sslclient/pavel_curl.pem"

echo "--- conf-start 1"
POST_DATA='{ "jetconf:input": {"name": "Edit 1", "options": "config"} }'
URL="https://127.0.0.1:8443/restconf/operations/jetconf:conf-start"
curl --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST -d "$POST_DATA" "$URL"

echo "--- DELETE album Wasting Time"
URL="https://127.0.0.1:8443/restconf/data/example-jukebox:jukebox/library/artist=New%20Artist/album=Wasting%20Time"
curl --http2 -k --cert-type PEM -E $CLIENT_CERT -X DELETE -d "$POST_DATA" "$URL"

echo "--- conf-commit"
URL="https://127.0.0.1:8443/restconf/operations/jetconf:conf-commit"
curl --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST "$URL"

