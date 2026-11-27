# Runtime-only image: the binary is cross-compiled on the operator's machine (same
# workflow as remote-monitor and the nervctf-proxy it replaces) and copied in here,
# not built inside Docker.
#
# No ca-certificates needed, unlike nervctf-proxy: the tap makes no TLS client
# connections of its own — it relays bytes and never terminates a protocol.
FROM debian:bookworm-slim
COPY nervctf-tap /usr/local/bin/nervctf-tap
ENTRYPOINT ["/usr/local/bin/nervctf-tap"]
