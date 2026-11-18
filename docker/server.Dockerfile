# NovaDB server runtime image. Build the binary first with the builder image:
#   docker run --rm -v "$PWD":/src -w /src --entrypoint cargo novadb-builder build --release --locked -p novadb-server
#   cp target/release/novadb-server docker/ && docker build -f docker/server.Dockerfile -t novadb-server docker/
# Run (data in a volume; publish only on loopback unless you really mean it):
#   docker run -d --name novadb --read-only --cap-drop ALL --security-opt no-new-privileges \
#     -p 127.0.0.1:3307:3307 -v novadb-data:/var/lib/novadb novadb-server
FROM debian:bookworm-slim
RUN useradd -r -u 10003 -M -d /var/lib/novadb -s /usr/sbin/nologin novadb \
 && mkdir -p /var/lib/novadb && chown novadb:novadb /var/lib/novadb && chmod 700 /var/lib/novadb
COPY novadb-server /usr/local/bin/novadb-server
USER novadb
VOLUME /var/lib/novadb
EXPOSE 3307
# Inside the container the listener must bind all interfaces so -p can reach it; limit
# exposure with -p 127.0.0.1:3307:3307 (TLS + Argon2id auth are always on).
ENTRYPOINT ["/usr/local/bin/novadb-server", "--data-dir", "/var/lib/novadb", "--listen", "[::]:3307"]
