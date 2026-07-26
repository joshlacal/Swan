FROM swift:6.1-jammy AS build
WORKDIR /workspace
COPY Petrel /workspace/Petrel
COPY Swan /workspace/Swan
WORKDIR /workspace/Swan
RUN swift build -c release --product swan

FROM ubuntu:24.04
RUN useradd --system --create-home --home-dir /var/lib/swan swan
COPY --from=build /workspace/Swan/.build/release/swan /usr/local/bin/swan
USER swan
WORKDIR /var/lib/swan
EXPOSE 3000
ENTRYPOINT ["swan"]
