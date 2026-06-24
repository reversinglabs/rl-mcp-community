# Build stage: install dependencies (dev image has pip and shell)
FROM cgr.dev/chainguard/python:latest-dev AS builder
USER root

# If behind a corporate proxy with SSL inspection, add your CA certificate:
# COPY your-ca-cert.pem /usr/local/share/ca-certificates/
# RUN update-ca-certificates

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir . --prefix=/install && \
    mkdir -p /app/reports /output && \
    touch /app/reports/.keep /output/.keep

# Runtime stage: Chainguard distroless — no shell, no pip, minimal attack surface
FROM cgr.dev/chainguard/python:latest

COPY --from=builder /install/lib /usr/lib
COPY --from=builder /install/bin /usr/bin
COPY --from=builder --chown=nonroot:nonroot /app /app
COPY --from=builder --chown=nonroot:nonroot /output /output

WORKDIR /app
CMD ["/usr/bin/rl-mcp-community"]
