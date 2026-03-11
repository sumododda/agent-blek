FROM golang:1.23-bookworm AS builder

# Install ProjectDiscovery tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/hahwul/dalfox/v2@latest

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    python3 \
    python3-pip \
    sqlmap \
    ca-certificates \
    chromium \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/* /usr/local/bin/

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

RUN useradd -m -s /bin/bash scanner
USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["/bin/bash"]
