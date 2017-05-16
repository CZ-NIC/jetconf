#!/bin/bash

CLIENT_CERT="/home/pspirek/sslclient/pavel_curl.pem"

echo "--- conf-start 1"
POST_DATA='{ "jetconf:input": {"name": "Edit 1", "options": "config"} }'
URL="https://127.0.0.1:8443/restconf/operations/jetconf:conf-start"
curl --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST -d "$POST_DATA" "$URL"

echo "--- POST new artist"
POST_DATA="@jb_artist_input.json"
URL="https://127.0.0.1:8443/restconf/data/example-jukebox:jukebox/library"
curl --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST -d "$POST_DATA" "$URL"

echo "--- conf-commit"
URL="https://127.0.0.1:8443/restconf/operations/jetconf:conf-commit"
curl --http2 -k --cert-type PEM -E $CLIENT_CERT -X POST "$URL"

