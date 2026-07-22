package main

import (
	"bufio"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type h1Conn struct {
	conn     net.Conn
	br       *bufio.Reader
	host     string
	lastUsed time.Time
	created  time.Time
}

type h2Conn struct {
	cc      *http2.ClientConn
	host    string
	created time.Time
}

type Pool struct {
	h2mu         sync.Mutex
	h2conns      map[string][]*h2Conn
	h2MaxPerHost int

	h1mu      sync.Mutex
	h1conns   map[string][]*h1Conn
	h1MaxIdle int

	idleTimeout time.Duration
	maxAge      time.Duration

	closeOnce sync.Once
}

func NewPool(h2Max, h1Max int, idleTimeout, maxAge time.Duration) *Pool {
	p := &Pool{
		h2conns:      make(map[string][]*h2Conn),
		h2MaxPerHost: h2Max,
		h1conns:      make(map[string][]*h1Conn),
		h1MaxIdle:    h1Max,
		idleTimeout:  idleTimeout,
		maxAge:       maxAge,
	}
	go p.cleanupLoop()
	return p
}

// ── H2 Pool ──
// Multiplexed: conn stays in pool during use, removed only when dead.

func (p *Pool) H2Get(host string) *http2.ClientConn {
	p.h2mu.Lock()
	defer p.h2mu.Unlock()

	conns := p.h2conns[host]
	for i := len(conns) - 1; i >= 0; i-- {
		c := conns[i]
		state := c.cc.State()
		if state.Closed {
			c.cc.Close()
			conns = append(conns[:i], conns[i+1:]...)
			continue
		}
		if time.Since(c.created) > p.maxAge {
			c.cc.Close()
			conns = append(conns[:i], conns[i+1:]...)
			continue
		}
		p.h2conns[host] = conns
		return c.cc
	}
	p.h2conns[host] = conns
	return nil
}

func (p *Pool) H2Put(host string, cc *http2.ClientConn) {
	p.h2mu.Lock()
	defer p.h2mu.Unlock()

	conns := p.h2conns[host]
	if len(conns) >= p.h2MaxPerHost {
		cc.Close()
		return
	}
	p.h2conns[host] = append(conns, &h2Conn{
		cc: cc, host: host, created: time.Now(),
	})
}

func (p *Pool) H2Count() int {
	p.h2mu.Lock()
	defer p.h2mu.Unlock()
	total := 0
	for _, conns := range p.h2conns {
		total += len(conns)
	}
	return total
}

// ── H1 Pool ──
// Exclusive: removed on get, returned on body-close.

func (p *Pool) H1Get(host string) *h1Conn {
	p.h1mu.Lock()
	defer p.h1mu.Unlock()

	conns := p.h1conns[host]
	for i := len(conns) - 1; i >= 0; i-- {
		c := conns[i]
		conns = append(conns[:i], conns[i+1:]...)

		if time.Since(c.lastUsed) > p.idleTimeout {
			c.conn.Close()
			continue
		}
		if time.Since(c.created) > p.maxAge {
			c.conn.Close()
			continue
		}
		p.h1conns[host] = conns
		return c
	}
	p.h1conns[host] = conns
	return nil
}

func (p *Pool) H1Put(c *h1Conn) {
	p.h1mu.Lock()
	defer p.h1mu.Unlock()

	c.lastUsed = time.Now()
	conns := p.h1conns[c.host]
	if len(conns) >= p.h1MaxIdle {
		c.conn.Close()
		return
	}
	p.h1conns[c.host] = append(conns, c)
}

func (p *Pool) H1Count() int {
	p.h1mu.Lock()
	defer p.h1mu.Unlock()
	total := 0
	for _, conns := range p.h1conns {
		total += len(conns)
	}
	return total
}

// ── Background Cleanup ──

func (p *Pool) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		p.cleanup()
	}
}

func (p *Pool) cleanup() {
	now := time.Now()

	p.h2mu.Lock()
	for host, conns := range p.h2conns {
		kept := conns[:0]
		for _, c := range conns {
			state := c.cc.State()
			if state.Closed || now.Sub(c.created) > p.maxAge {
				c.cc.Close()
			} else {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(p.h2conns, host)
		} else {
			p.h2conns[host] = kept
		}
	}
	p.h2mu.Unlock()

	p.h1mu.Lock()
	for host, conns := range p.h1conns {
		kept := conns[:0]
		for _, c := range conns {
			if now.Sub(c.lastUsed) > p.idleTimeout ||
				now.Sub(c.created) > p.maxAge {
				c.conn.Close()
			} else {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(p.h1conns, host)
		} else {
			p.h1conns[host] = kept
		}
	}
	p.h1mu.Unlock()
}

func (p *Pool) Close() {
	p.closeOnce.Do(func() {
		p.h2mu.Lock()
		for _, conns := range p.h2conns {
			for _, c := range conns {
				c.cc.Close()
			}
		}
		p.h2conns = make(map[string][]*h2Conn)
		p.h2mu.Unlock()

		p.h1mu.Lock()
		for _, conns := range p.h1conns {
			for _, c := range conns {
				c.conn.Close()
			}
		}
		p.h1conns = make(map[string][]*h1Conn)
		p.h1mu.Unlock()
	})
}
