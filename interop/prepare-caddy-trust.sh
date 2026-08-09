#!/usr/bin/env sh
set -eu

source_certificate="/caddy-data/caddy/pki/authorities/local/root.crt"
trust_directory="/prepared-trust"
destination_certificate="${trust_directory}/caddy-local-root.crt"
destination_bundle="${trust_directory}/ca-certificates.crt"
system_bundle="/etc/ssl/certs/ca-certificates.crt"

if [ -L "$source_certificate" ] || [ ! -s "$source_certificate" ]; then
    echo "caddy local CA certificate is missing or unsafe" >&2
    exit 1
fi
if [ "$(head -n 1 "$source_certificate")" != "-----BEGIN CERTIFICATE-----" ]; then
    echo "caddy local CA certificate is invalid" >&2
    exit 1
fi
if [ ! -s "$system_bundle" ]; then
    echo "system CA certificate bundle is missing" >&2
    exit 1
fi

# The trust volume contains public CA material and is shared with reference
# services that deliberately run under non-Swan UIDs.
install -d -o root -g root -m 0755 "$trust_directory"
install -o swan -g swan -m 0444 "$source_certificate" "$destination_certificate"
temporary_bundle="$(mktemp "$trust_directory/.ca-certificates.XXXXXX")"
cat "$system_bundle" > "$temporary_bundle"
printf '\n' >> "$temporary_bundle"
cat "$source_certificate" >> "$temporary_bundle"
chown swan:swan "$temporary_bundle"
chmod 0444 "$temporary_bundle"
mv -f "$temporary_bundle" "$destination_bundle"
echo "caddy local CA trust copy prepared"
