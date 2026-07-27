FROM swift:6.1-jammy AS build
# Keep the Swift 6.1/Jammy build baseline explicit and install the same
# system-library development surface SwiftPM uses on a clean Linux builder.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libsodium-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY Petrel /workspace/Petrel
COPY Swan /workspace/Swan
WORKDIR /workspace/Swan
RUN swift build -c release --product swan

FROM ubuntu:24.04
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libsodium23 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/swan swan
COPY --from=build /workspace/Swan/.build/release/swan /usr/local/bin/swan
COPY interop/bootstrap-local-space.sh /usr/local/bin/swan-interop-bootstrap
RUN chmod +x /usr/local/bin/swan-interop-bootstrap
USER swan
WORKDIR /var/lib/swan
EXPOSE 3000
ENTRYPOINT ["swan"]
