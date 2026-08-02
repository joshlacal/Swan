FROM swift:6.1-jammy@sha256:12be34a341945adb64914405ed7b568fcb2d35edbd63a3755007e47dce59456e AS build
# Keep the Swift 6.1/Jammy build baseline explicit and install the same
# system-library development surface SwiftPM uses on a clean Linux builder.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libsodium-dev pkg-config \
        libsecret-1-dev \
        libglib2.0-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY Petrel /workspace/Petrel
COPY Swan /workspace/Swan
WORKDIR /workspace/Swan
RUN swift build -c release --product swan

FROM swift:6.1-jammy@sha256:12be34a341945adb64914405ed7b568fcb2d35edbd63a3755007e47dce59456e
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl libsodium23 libsecret-1-0 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/swan swan \
    && mkdir -p /etc/swan/interop \
    && touch /etc/swan/interop/notification-config.json
COPY Swan/interop/notification-config.json /etc/swan/interop/notification-config.json
COPY --from=build /workspace/Swan/.build/release/swan /usr/local/bin/swan
COPY Swan/Profiles /usr/local/share/swan/Profiles
COPY Swan/interop/bootstrap-local-space.sh /usr/local/bin/swan-interop-bootstrap
COPY Swan/interop/prepare-interop-secrets.sh /usr/local/bin/swan-interop-prepare-secrets
COPY Swan/interop/prepare-caddy-trust.sh /usr/local/bin/swan-interop-caddy-trust
COPY Swan/Scripts/validate-live-interop-artifact.py /usr/local/bin/swan-validate-live-interop-artifact
RUN chmod +x \
    /usr/local/bin/swan-interop-bootstrap \
    /usr/local/bin/swan-interop-prepare-secrets \
    /usr/local/bin/swan-interop-caddy-trust \
    /usr/local/bin/swan-validate-live-interop-artifact
USER swan
WORKDIR /var/lib/swan
EXPOSE 3000
ENTRYPOINT ["swan"]
