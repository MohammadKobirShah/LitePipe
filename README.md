# LitePipe

Lossless compression proxy for slow connections. Browse any website at 100kbps without quality degradation. Transparent to destination servers — original IP, User-Agent, and TLS fingerprint all preserved.

Built for people stuck on slow connections who refuse to accept degraded images and broken pages.

## What It Does

```
Client → Nginx → Go (utls) → Destination
              ↑           ↑
      URL rewrite   Browser-matched
      Gzip L9       TLS fingerprint
      Caching       (JA3/JA4 spoof)
```

- **Lossless compression** — Gzip level 9 on all text content. Images stay original quality.
- **TLS fingerprint spoofing** — Go process using utls matches Chrome/Firefox/Safari/iOS/Edge ClientHello exactly. Cloudflare, Google, Facebook can't distinguish from real browser.
- **Client IP preserved** — Destination sees real client IP via `X-Forwarded-For` (CDN edge pattern).
- **Full header passthrough** — User-Agent, Accept, Cookie, Referer, Sec-Fetch-* all forwarded untouched.
- **Transparent URL rewriting** — HTML attributes, CSS `url()`, `srcset`, JS `fetch()`, `XMLHttpRequest`, `createElement`, `MutationObserver`, `history.pushState` all patched server-side + client-side.
- **Connection pooling** — H2 multiplexed per-host, H1 keep-alive with EOF-aware body wrapper.
- **Auth layer** — Cookie-based token auth. Strip auth cookie before forwarding. Open proxy mode when unconfigured.
- **Cloudflare Tunnel** — Optional. Set `CLOUDFLARED_TOKEN` env and it activates automatically.

## Architecture

| Layer | Tech | Responsibility |
|-------|------|----------------|
| Edge | OpenResty (Nginx) | Rate limiting, caching, Gzip L9, URL rewriting (Lua), header filtering |
| TLS | Go + utls | Browser fingerprint matching, H2/H1 connection pooling, auth, stats |
| Tunnel | cloudflared | Optional Cloudflare Tunnel for zero-config HTTPS + DDoS protection |

### Request Flow

1. Client requests `https://litepipe.app/browse/https://youtube.com/watch?v=xxx`
2. Nginx Lua parses target URL from path, extracts host, protocol, page path
3. Nginx forwards to Go on `127.0.0.1:8081` with `X-Target-URL` header
4. Go checks auth cookie → strips auth cookie from forwarded headers
5. Go picks TLS fingerprint matching client's User-Agent (Chrome UA → Chrome ClientHello)
6. Go dials destination with spoofed TLS, forwards all original headers + client IP
7. Destination responds — sees browser TLS fingerprint + real headers + real IP
8. Go streams response back to Nginx
9. Nginx Lua rewrites all URLs in HTML/CSS to proxied form, injects JS interceptor
10. Nginx applies Gzip L9, serves to client

## Quick Start

### Docker (Local)

```bash
git clone https://github.com/yourname/litepipe.git
cd litepipe
docker compose up --build -d
```

Open `http://localhost:8080` — type any URL and go.

### Railway

```bash
npm i -g @railway/cli
railway login
railway init
railway up
```

Set `AUTH_TOKENS` in Railway dashboard → Variables.

### Render

1. Push to GitHub
2. New Web Service → Docker → connect repo
3. Render reads `render.yaml` automatically

## Configuration

All config via environment variables. No config files to edit.

| Env Var | Default | Description |
|---------|---------|-------------|
| `PORT` | `80` | Nginx listen port (auto-set by Railway/Render) |
| `AUTH_TOKENS` | *(empty)* | `token:label,token2:label2` — empty = open proxy |
| `FP_CHROME` | *(auto)* | Pin Chrome TLS fingerprint version (e.g. `120`) |
| `FP_FIREFOX` | *(auto)* | Pin Firefox version |
| `FP_SAFARI` | *(auto)* | Pin Safari version |
| `FP_IOS` | *(auto)* | Pin iOS version |
| `FP_EDGE` | *(auto)* | Pin Edge version |
| `H2_MAX_CONNS` | `3` | Max H2 pooled connections per host |
| `H1_MAX_IDLE` | `5` | Max idle H1 connections per host |
| `CONN_IDLE_TIMEOUT` | `60s` | Idle connection expiry |
| `CONN_MAX_AGE` | `10m` | Max connection age before forced close |
| `DIAL_TIMEOUT` | `10s` | TLS dial timeout |
| `CLOUDFLARED_TOKEN` | *(empty)* | Cloudflare Tunnel token — empty = disabled |

### Auth Setup

```bash
# Single user
AUTH_TOKENS=mySecret123:admin

# Multiple users
AUTH_TOKENS=token1:alice,token2:bob,token3:charlie
```

When `AUTH_TOKENS` is set, users see a login page at `/login`. Auth cookie `_ds_auth` is HttpOnly, SameSite=Lax, 30-day expiry. Cookie is stripped before forwarding to destination.

When empty, proxy runs in open mode (no auth). Not recommended for public deployment.

### Fingerprint Pinning

By default, LitePipe auto-detects the best TLS fingerprint from the User-Agent. For stricter control:

```bash
FP_CHROME=120    # Pin to Chrome 120 ClientHello exactly
FP_FIREFOX=120   # Pin to Firefox 120
```

Empty or `auto` = let utls pick the latest available spec for that browser family.

### Cloudflare Tunnel

1. Go to Cloudflare Zero Trust → Networks → Tunnels → Create
2. Name the tunnel, copy the token
3. Set ingress rule: `litepipe.yourdomain.com` → `http://localhost:80`
4. Set `CLOUDFLARED_TOKEN` env var in your deployment
5. LitePipe starts cloudflared automatically on boot

When unset, cloudflared doesn't start — zero overhead.

## Admin API

```bash
# Stats (requires auth cookie or bearer token)
curl -b "_ds_auth=mySecret123" https://litepipe.app/admin

# Response:
{
  "uptime": "2h35m",
  "total_requests": 1847,
  "auth_failures": 3,
  "h2_requests": 1620,
  "h1_requests": 227,
  "active_h2_conns": 4,
  "active_h1_conns": 2,
  "per_host": {
    "www.youtube.com": {"requests": 890, "h2": 870, "h1": 20},
    "www.facebook.com": {"requests": 620, "h2": 600, "h1": 20}
  },
  "per_token": [
    {"label": "admin", "token_masked": "mySe...2123", "requests": 1847}
  ]
}
```

Tokens are masked in API output — first 4 + `...` + last 4 characters.

## Bandwidth at 100kbps

| Content | Original | Gzip L9 | Load Time |
|---------|----------|---------|-----------|
| HTML page (50KB) | 50 KB | ~8 KB | ~0.6s |
| CSS bundle (200KB) | 200 KB | ~25 KB | ~2s |
| JS bundle (300KB) | 300 KB | ~70 KB | ~5.6s |
| PNG image (500KB) | 500 KB | ~470 KB | ~37.6s |
| SVG (20KB) | 20 KB | ~4 KB | ~0.3s |
| Google search (95KB) | 95 KB | ~14 KB | ~1.1s |
| YouTube watch page (850KB) | 850 KB | ~180 KB | ~14.4s |

Text content: 75-85% bandwidth reduction. Images: lossless (metadata strip only).

## Project Structure

```
litepipe/
├── Dockerfile              # Multi-stage: Go build + OpenResty + cloudflared
├── docker-compose.yml
├── railway.toml
├── render.yaml
├── entrypoint.sh           # Starts Go + nginx + optional cloudflared
├── nginx.conf.template     # Edge config: caching, gzip, rate limit, Lua hooks
├── lua/
│   └── proxy.lua           # URL rewriting, header filtering, JS interceptor
├── html/
│   └── index.html          # Landing page with URL input
└── tlsspoof/
    ├── go.mod
    ├── main.go             # Server, proxy handler, login, admin
    ├── fingerprint.go      # Browser fingerprint selection + pinning
    ├── pool.go             # H2/H1 connection pools with cleanup
    ├── spoofer.go          # utls dialing, RoundTrip, body wrapper
    ├── auth.go             # Token management, cookie handling
    └── stats.go            # Request stats, per-host/per-token tracking
```

## What Destination Servers See

```
GET /watch?v=dQw4w9WgXcQ HTTP/2
Host: www.youtube.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)... Chrome/131...
Accept: text/html,application/xhtml+xml...
Accept-Language: en-US,en;q=0.9
Cookie: VISITOR_INFO1_LIVE=xxx; YSC=yyy
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
X-Forwarded-For: 203.0.113.45    ← client's real IP
Accept-Encoding: identity          ← only deviation (needed for rewriting)
```

TLS fingerprint: matches Chrome exactly (JA3/JA4).
HTTP headers: client's real headers forwarded untouched.
No `Via`, `X-Proxy-ID`, `X-Served-By` — nothing reveals middleware.

## License

MIT
