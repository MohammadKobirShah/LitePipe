package main

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

type AuthManager struct {
	tokens map[string]string // token → label
}

func NewAuthManager(envTokens string) AuthManager {
	m := AuthManager{tokens: make(map[string]string)}
	if envTokens == "" {
		return m
	}

	for _, pair := range strings.Split(envTokens, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		token := strings.TrimSpace(parts[0])
		label := "user"
		if len(parts) > 1 {
			label = strings.TrimSpace(parts[1])
		}
		if token != "" {
			m.tokens[token] = label
		}
	}
	return m
}

func (m AuthManager) Enabled() bool {
	return len(m.tokens) > 0
}

func (m AuthManager) TokenCount() int {
	return len(m.tokens)
}

func (m AuthManager) Valid(token string) bool {
	if !m.Enabled() {
		return true
	}
	if token == "" {
		return false
	}
	for t := range m.tokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

func (m AuthManager) Label(token string) string {
	if label, ok := m.tokens[token]; ok {
		return label
	}
	return "unknown"
}

func (m AuthManager) ExtractToken(r *http.Request) string {
	if c, err := r.Cookie("_ds_auth"); err == nil && c.Value != "" {
		return c.Value
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func (m *AuthManager) StripAuthCookie(cookieHeader string) string {
	cookies := strings.Split(cookieHeader, ";")
	kept := []string{}
	for _, c := range cookies {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(c), "_ds_auth=") {
			continue
		}
		kept = append(kept, c)
	}
	return strings.Join(kept, "; ")
}

// MaskToken returns first 4 + ... + last 4 for safe display
func MaskToken(t string) string {
	if len(t) <= 2 {
		return t + "..."
	}
	if len(t) <= 8 {
		return t[:2] + "..."
	}
	return t[:4] + "..." + t[len(t)-4:]
}
