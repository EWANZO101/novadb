# NovaDB dashboard runtime image. Build the binary first with the builder image:
#   docker run --rm -v "$PWD":/src -w /src --entrypoint cargo novadb-builder build --release -p novadb-dashboard
#   cp target/release/novadb-dashboard docker/ && docker build -f docker/dashboard.Dockerfile -t novadb-dashboard docker/
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10002 -M -d /data -s /usr/sbin/nologin novadb \
 && mkdir -p /data && chown novadb:novadb /data && chmod 700 /data
COPY novadb-dashboard /usr/local/bin/novadb-dashboard
USER novadb
ENV NOVADB_DASH_DATA=/data NOVADB_DASH_LISTEN=127.0.0.1:9620
VOLUME /data
HEALTHCHECK --interval=60s --timeout=5s CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/9620 || exit 1"]
ENTRYPOINT ["/usr/local/bin/novadb-dashboard"]
