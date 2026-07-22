package main

import (
	"sync"
	"time"
)

type hostStat struct {
	Requests int64 `json:"requests"`
	H2       int64 `json:"h2"`
	H1       int64 `json:"h1"`
}

// [BUGFIX #9] tokenStat uses masked token instead of raw
type tokenStat struct {
	Label    string `json:"label"`
	Token    string `json:"token_masked"`
	Requests int64  `json:"requests"`
}

type StatsSnapshot struct {
	Uptime        string                `json:"uptime"`
	TotalRequests int64                 `json:"total_requests"`
	AuthFailures  int64                 `json:"auth_failures"`
	H2Requests    int64                 `json:"h2_requests"`
	H1Requests    int64                 `json:"h1_requests"`
	ActiveH2Conns int                   `json:"active_h2_conns"`
	ActiveH1Conns int                   `json:"active_h1_conns"`
	PerHost       map[string]*hostStat  `json:"per_host"`
	PerToken      []tokenStat           `json:"per_token"`
}

type Stats struct {
	mu            sync.RWMutex
	startTime     time.Time
	totalRequests int64
	authFailures  int64
	h2Requests    int64
	h1Requests    int64
	perHost       map[string]*hostStat
	perToken      map[string]*tokenStat
}

func NewStats() *Stats {
	return &Stats{
		startTime: time.Now(),
		perHost:   make(map[string]*hostStat),
		perToken:  make(map[string]*tokenStat),
	}
}

func (s *Stats) IncRequest(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalRequests++
	if _, ok := s.perHost[host]; !ok {
		s.perHost[host] = &hostStat{}
	}
	s.perHost[host].Requests++
}

func (s *Stats) IncH2(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.h2Requests++
	if hs, ok := s.perHost[host]; ok {
		hs.H2++
	}
}

func (s *Stats) IncH1(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.h1Requests++
	if hs, ok := s.perHost[host]; ok {
		hs.H1++
	}
}

func (s *Stats) IncAuthFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authFailures++
}

func (s *Stats) IncTokenRequest(token, label string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.perToken[token]; !ok {
		s.perToken[token] = &tokenStat{
			Label: label,
			Token: MaskToken(token),
		}
	}
	s.perToken[token].Requests++
}

func (s *Stats) Snapshot() StatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ph := make(map[string]*hostStat)
	for k, v := range s.perHost {
		cp := *v
		ph[k] = &cp
	}

	// [BUGFIX #9] Return slice with masked tokens, never raw
	pt := make([]tokenStat, 0, len(s.perToken))
	for _, v := range s.perToken {
		pt = append(pt, *v)
	}

	return StatsSnapshot{
		Uptime:        time.Since(s.startTime).Round(time.Second).String(),
		TotalRequests: s.totalRequests,
		AuthFailures:  s.authFailures,
		H2Requests:    s.h2Requests,
		H1Requests:    s.h1Requests,
		PerHost:       ph,
		PerToken:      pt,
	}
}
