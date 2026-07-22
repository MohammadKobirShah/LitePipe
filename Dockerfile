# ════════════════════════════════════════════════════════════════
# Stage 1: Build Go TLS Spoofer
# ════════════════════════════════════════════════════════════════
FROM golang:1.22-bookworm AS go-builder

WORKDIR /build
COPY tlsspoof/go.mod ./
RUN go mod download 2>/dev/null || true
COPY tlsspoof/ ./
RUN go mod tidy && CGO_ENABLED=0 go build -o /tlsspoof -ldflags="-s -w" .

# ════════════════════════════════════════════════════════════════
# Stage 2: OpenResty + Go Binary + cloudflared
# ════════════════════════════════════════════════════════════════
FROM openresty/openresty:1.25.3.1-bookworm

COPY --from=go-builder /tlsspoof /usr/local/bin/tlsspoof

RUN opm get ledgetech/lua-resty-http

# cloudflared for optional Cloudflare Tunnel
RUN curl -L -o /usr/local/bin/cloudflared \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    && chmod +x /usr/local/bin/cloudflared

RUN mkdir -p /tmp/cache /tmp/client_body /tmp/proxy_temp \
    /etc/openresty/lua /usr/local/openresty/nginx/html

COPY nginx.conf.template /usr/local/openresty/nginx/conf/nginx.conf.template
COPY lua/ /etc/openresty/lua/
COPY html/ /usr/local/openresty/nginx/html/
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh /usr/local/bin/tlsspoof /usr/local/bin/cloudflared

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-80}/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
