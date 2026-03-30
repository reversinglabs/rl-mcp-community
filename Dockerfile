FROM python:3.12-slim

# If behind a corporate proxy with SSL inspection, add your CA certificate:
# COPY your-ca-cert.pem /usr/local/share/ca-certificates/
# RUN update-ca-certificates

WORKDIR /app
COPY . /app

RUN mkdir -p /app/reports && \
    pip install .

CMD ["rl-mcp-community"]
