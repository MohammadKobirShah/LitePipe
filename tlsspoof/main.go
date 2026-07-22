// ════════════════════════════════════════════════════════════════
// LitePipe TLS Spoofer v3 — Bug Bounty Fixed
// ════════════════════════════════════════════════════════════════

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Listen       string
	DialTimeout  time.Duration
	H2MaxConns   int
	H1MaxIdle    int
	IdleTimeout  time.Duration
	MaxAge       time.Duration
	Fingerprints FingerprintConfig
}

func loadConfig() *Config {
	cfg := &Config{
		Listen:      getEnv("LISTEN", "127.0.0.1:8081"),
		DialTimeout: getEnvDuration("DIAL_TIMEOUT", 10*time.Second),
		H2MaxConns:  getEnvInt("H2_MAX_CONNS", 3),
		H1MaxIdle:   getEnvInt("H1_MAX_IDLE", 5),
		IdleTimeout: getEnvDuration("CONN_IDLE_TIMEOUT", 60*time.Second),
		MaxAge:      getEnvDuration("CONN_MAX_AGE", 10*time.Minute),
		Fingerprints: FingerprintConfig{
			Chrome:  os.Getenv("FP_CHROME"),
			Firefox: os.Getenv("FP_FIREFOX"),
			Safari:  os.Getenv("FP_SAFARI"),
			IOS:     os.Getenv("FP_IOS"),
			Edge:    os.Getenv("FP_EDGE"),
		},
	}
	flag.StringVar(&cfg.Listen, "listen", cfg.Listen, "listen address")
	flag.DurationVar(&cfg.DialTimeout, "dial-timeout", cfg.DialTimeout, "dial timeout")
	flag.Parse()
	return cfg
}

type Server struct {
	spoofer *Spoofer
	auth    AuthManager
	stats   *Stats
	pool    Pool
	cfg     *Config
}

func main() {
	cfg := loadConfig()

	auth := NewAuthManager(os.Getenv("AUTH_TOKENS"))
	if !auth.Enabled() {
		log.Println("WARNING: AUTH_TOKENS not set — running as open proxy")
	}

	pool := NewPool(cfg.H2MaxConns, cfg.H1MaxIdle, cfg.IdleTimeout, cfg.MaxAge)
	spoofer := NewSpoofer(pool, cfg.DialTimeout, cfg.Fingerprints)
	stats := NewStats()

	srv := &Server{spoofer, auth, stats, pool, cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/login", srv.handleLogin)
	mux.HandleFunc("/admin", srv.handleAdmin)
	mux.Handle("/browse/", srv)

	httpServer := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
		<-sigChan
		log.Println("Shutting down Go server...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
		pool.Close()
	}()

	log.Printf("LitePipe TLS spoofer listening on %s", cfg.Listen)
	if auth.Enabled() {
		log.Printf("Auth: enabled (%d tokens)", auth.TokenCount())
	} else {
		log.Printf("Auth: disabled (open proxy)")
	}
	log.Printf("Pool: H2 max=%d/host, H1 idle=%d/host, idle=%s, maxAge=%s",
		cfg.H2MaxConns, cfg.H1MaxIdle, cfg.IdleTimeout, cfg.MaxAge)

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	log.Println("Server stopped")
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.auth.Enabled() {
		token := s.auth.ExtractToken(r)
		if token == "" || !s.auth.Valid(token) {
			s.stats.IncAuthFailure()
			redirect := r.URL.Path
			if r.URL.RawQuery != "" {
				redirect += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, "/login?redirect="+url.QueryEscape(redirect),
				http.StatusFound)
			return
		}
		s.stats.IncTokenRequest(token, s.auth.Label(token))
	}

	targetURL := r.Header.Get("X-Target-URL")
	if targetURL == "" {
		http.Error(w, "missing X-Target-URL", http.StatusBadRequest)
		return
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "invalid target URL", http.StatusBadRequest)
		return
	}

	upstreamReq, err := http.NewRequestWithContext(
		r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "failed to create upstream request",
			http.StatusInternalServerError)
		return
	}

	for name, values := range r.Header {
		lname := strings.ToLower(name)
		if lname == "x-target-url" || isHopByHop(lname) {
			continue
		}
		if lname == "cookie" && s.auth.Enabled() {
			for _, v := range values {
				v = s.auth.StripAuthCookie(v)
				if v != "" {
					upstreamReq.Header.Add(name, v)
				}
			}
			continue
		}
		for _, v := range values {
			upstreamReq.Header.Add(name, v)
		}
	}

	upstreamReq.Host = parsed.Host
	upstreamReq.ContentLength = r.ContentLength

	s.stats.IncRequest(parsed.Host)

	resp, err := s.spoofer.RoundTrip(upstreamReq)
	if err != nil {
		log.Printf("upstream error for %s: %v", targetURL, err)
		http.Error(w, fmt.Sprintf("upstream error: %v", err),
			http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for name, values := range resp.Header {
		if isHopByHop(strings.ToLower(name)) {
			continue
		}
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}

	w.WriteHeader(resp.StatusCode)

	if resp.ProtoMajor == 2 {
		s.stats.IncH2(parsed.Host)
	} else {
		s.stats.IncH1(parsed.Host)
	}

	io.Copy(w, resp.Body)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Enabled() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if r.Method == "GET" {
		redirect := r.URL.Query().Get("redirect")
		if redirect == "" || !strings.HasPrefix(redirect, "/") {
			redirect = "/"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, loginHTML, redirect)
		return
	}

	if r.Method == "POST" {
		r.ParseForm()
		token := r.FormValue("token")
		redirect := r.FormValue("redirect")
		if redirect == "" || !strings.HasPrefix(redirect, "/") {
			redirect = "/"
		}

		if s.auth.Valid(token) {
			http.SetCookie(w, &http.Cookie{
				Name:     "_ds_auth",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   2592000,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, redirect, http.StatusFound)
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, loginHTMLFail, redirect)
		}
	}
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if s.auth.Enabled() {
		token := s.auth.ExtractToken(r)
		if token == "" || !s.auth.Valid(token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
	}

	snap := s.stats.Snapshot()
	snap.ActiveH2Conns = s.pool.H2Count()
	snap.ActiveH1Conns = s.pool.H1Count()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap)
}

func isHopByHop(header string) bool {
	switch header {
	case "connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailer",
		"transfer-encoding", "upgrade":
		return true
	}
	return false
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		var i int
		fmt.Sscanf(v, "%d", &i)
		if i > 0 {
			return i
		}
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultVal
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LitePipe — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#0f0f1a;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.wrap{width:90%%;max-width:360px}
h1{font-size:1.4rem;color:#16c79a;margin-bottom:1rem;font-weight:700}
input{width:100%%;padding:14px;border:1px solid #2a2a3e;border-radius:10px;background:#1a1a2e;color:#e0e0e0;font-size:16px;margin-bottom:12px}
input:focus{outline:none;border-color:#16c79a}
button{width:100%%;padding:14px;border:none;border-radius:10px;background:#16c79a;color:#0f0f1a;font-weight:700;font-size:16px;cursor:pointer}
.sub{color:#555;font-size:.8rem;margin-top:1rem;text-align:center}
</style>
</head>
<body>
<div class="wrap">
<h1>LitePipe Login</h1>
<form method="POST" action="/login">
<input type="hidden" name="redirect" value="%s">
<input type="password" name="token" placeholder="Access token" autofocus>
<button type="submit">Unlock</button>
</form>
<p class="sub">Lossless compression proxy</p>
</div>
</body>
</html>`

const loginHTMLFail = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LitePipe — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#0f0f1a;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.wrap{width:90%%;max-width:360px}
h1{font-size:1.4rem;color:#e74c3c;margin-bottom:1rem;font-weight:700}
input{width:100%%;padding:14px;border:1px solid #2a2a3e;border-radius:10px;background:#1a1a2e;color:#e0e0e0;font-size:16px;margin-bottom:12px}
input:focus{outline:none;border-color:#16c79a}
button{width:100%%;padding:14px;border:none;border-radius:10px;background:#16c79a;color:#0f0f1a;font-weight:700;font-size:16px;cursor:pointer}
.err{color:#e74c3c;font-size:.85rem;margin-bottom:12px}
</style>
</head>
<body>
<div class="wrap">
<h1>LitePipe Login</h1>
<p class="err">Invalid token. Try again.</p>
<form method="POST" action="/login">
<input type="hidden" name="redirect" value="%s">
<input type="password" name="token" placeholder="Access token" autofocus>
<button type="submit">Unlock</button>
</form>
</div>
</body>
</html>`
