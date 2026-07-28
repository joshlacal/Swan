#!/usr/bin/env sh
set -eu

source_certificate="/caddy-data/caddy/pki/authorities/local/root.crt"
trust_directory="/prepared-trust"
destination_certificate="${trust_directory}/caddy-local-root.crt"

if [ -L "$source_certificate" ] || [ ! -s "$source_certificate" ]; then
    echo "caddy local CA certificate is missing or unsafe" >&2
    exit 1
fi
if [ "$(head -n 1 "$source_certificate")" != "-----BEGIN CERTIFICATE-----" ]; then
    echo "caddy local CA certificate is invalid" >&2
    exit 1
fi

install -d -o swan -g swan -m 0700 "$trust_directory"
install -o swan -g swan -m 0444 "$source_certificate" "$destination_certificate"
echo "caddy local CA trust copy prepared"
