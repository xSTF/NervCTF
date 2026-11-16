# Runtime-only image: the binary is cross-compiled on the operator's machine (same
# workflow as remote-monitor) and copied in here, not built inside Docker.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY nervctf-proxy /usr/local/bin/nervctf-proxy
ENTRYPOINT ["/usr/local/bin/nervctf-proxy"]
