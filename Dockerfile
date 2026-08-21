FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS account-web-build
WORKDIR /workspace/Swan/web
COPY Swan/web/package.json Swan/web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY Swan/web/ ./
RUN npm run prepare && npm run check && npm run build

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
COPY Swan /workspace/Swan
WORKDIR /workspace/Swan
RUN swift build -c release --product swan

FROM swift:6.1-jammy@sha256:12be34a341945adb64914405ed7b568fcb2d35edbd63a3755007e47dce59456e AS runtime
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl libsodium23 libsecret-1-0 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/swan swan
COPY --from=build /workspace/Swan/.build/release/swan /usr/local/bin/swan
COPY --from=account-web-build /workspace/Swan/web/build /usr/local/share/swan/account
COPY Swan/Profiles /usr/local/share/swan/Profiles
COPY Swan/interop/bootstrap-local-space.sh /usr/local/bin/swan-interop-bootstrap
COPY Swan/interop/prepare-interop-secrets.sh /usr/local/bin/swan-interop-prepare-secrets
COPY Swan/interop/prepare-caddy-trust.sh /usr/local/bin/swan-interop-caddy-trust
COPY Swan/Scripts/validate-live-interop-artifact.py /usr/local/bin/swan-validate-live-interop-artifact
COPY Swan/Scripts/project-corruption-recovery-witness.py /usr/local/bin/swan-project-corruption-recovery-witness
RUN chmod +x \
    /usr/local/bin/swan-interop-bootstrap \
    /usr/local/bin/swan-interop-prepare-secrets \
    /usr/local/bin/swan-interop-caddy-trust \
    /usr/local/bin/swan-validate-live-interop-artifact \
    /usr/local/bin/swan-project-corruption-recovery-witness
USER swan
WORKDIR /var/lib/swan
EXPOSE 3000
ENTRYPOINT ["swan"]

# Laboratory-only stage. `interop/notification-config.json` is disposable lab
# routing — peer pins for `reference-plc`, a `laboratory: true` PLC policy, a
# `did:web:interop-swan-managing-service` audience — and it used to be baked
# into the runtime image with `mkdir`/`touch`/`COPY`, so every production image
# shipped a laboratory PLC configuration one `--notification-config` flag away
# from being loaded. It now lives only here, and the only consumer is the lab's
# `swan-notification-config-init` service, which publishes it into a named
# volume the runtime mounts read-only. A host bind is deliberately not used:
# `Scripts/verify-interop-lab.sh` rejects a bind for that path.
FROM runtime AS interop-notification-config
USER root
COPY Swan/interop/notification-config.json /usr/local/share/swan/interop/notification-config.json
USER swan

# The default (last) stage is the clean runtime. `docker build` with no
# `--target` must never produce an image that carries laboratory configuration,
# so this trailing stage is what keeps the lab stage above unreachable by
# accident.
FROM runtime
