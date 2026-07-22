#!/bin/bash
set -e

PORT=${PORT:-80}

envsubst '${PORT}' < /usr/local/openresty/nginx/conf/nginx.conf.template \
    > /usr/local/openresty/nginx/conf/nginx.conf
openresty -t

# ── Start TLS Spoofer ──
echo "LitePipe: Starting TLS spoofer on 127.0.0.1:8081..."
/usr/local/bin/tlsspoof -listen 127.0.0.1:8081 &
SPOOFER_PID=$!

sleep 1
if ! kill -0 $SPOOFER_PID 2>/dev/null; then
    echo "LitePipe: TLS spoofer failed to start!"
    exit 1
fi
echo "LitePipe: TLS spoofer started (PID: $SPOOFER_PID)"

# ── Optional: Cloudflare Tunnel ──
CF_PID=""
if [ -n "$CLOUDFLARED_TOKEN" ]; then
    echo "LitePipe: Starting Cloudflare Tunnel..."
    cloudflared tunnel --no-autoupdate run --token "$CLOUDFLARED_TOKEN" &
    CF_PID=$!
    sleep 2
    if kill -0 $CF_PID 2>/dev/null; then
        echo "LitePipe: Cloudflare Tunnel started (PID: $CF_PID)"
    else
        echo "LitePipe: WARNING — Cloudflare Tunnel failed, continuing without it"
        CF_PID=""
    fi
else
    echo "LitePipe: Cloudflare Tunnel disabled (CLOUDFLARED_TOKEN not set)"
fi

# ── Graceful Shutdown ──
shutdown() {
    echo "LitePipe: Shutting down..."
    openresty -s quit 2>/dev/null || true
    kill -TERM $SPOOFER_PID 2>/dev/null || true
    if [ -n "$CF_PID" ]; then
        kill -TERM $CF_PID 2>/dev/null || true
    fi
    wait $SPOOFER_PID 2>/dev/null || true
    if [ -n "$CF_PID" ]; then
        wait $CF_PID 2>/dev/null || true
    fi
    wait $NGINX_PID 2>/dev/null || true
    echo "LitePipe: Shutdown complete."
    exit 0
}
trap shutdown TERM INT

# ── Start Nginx ──
echo "LitePipe: Starting nginx on port ${PORT}..."
openresty -g "daemon off;" &
NGINX_PID=$!

if [ -n "$CF_PID" ]; then
    wait -n $SPOOFER_PID $NGINX_PID $CF_PID 2>/dev/null || true
else
    wait -n $SPOOFER_PID $NGINX_PID 2>/dev/null || true
fi
shutdown
