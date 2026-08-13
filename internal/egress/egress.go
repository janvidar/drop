// Package egress serves the banner listeners used by the outbound test.
//
// The case being diagnosed is a network that blocks outbound traffic, which
// today reaches users as an unexplained inability to connect to any hub at
// all. Such networks typically permit a handful of ports and nothing else, so
// the test is simply: can the client reach us on 411, on 1511, on 5000.
//
// The banner is the part that matters. A bare successful connect proves
// nothing, because the most common cause of blocked egress is a transparent
// proxy or captive portal that accepts the connection itself and then does
// something else with it. Speaking first, with something only this service
// would say, distinguishes "the port is open" from "something intercepted me".
package egress

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// BannerFor renders the line sent on a given port.
func BannerFor(port int) string { return fmt.Sprintf("DROP/1 EGRESS %d\n", port) }

// writeTimeout bounds a banner write. The listener never reads, so a peer that
// refuses to accept data must not be able to hold a goroutine open.
const writeTimeout = 5 * time.Second

// Listener serves one port on all configured addresses.
type Listener struct {
	Port int
	Log  *slog.Logger

	// OnConnection is called for each accepted connection, for metrics.
	OnConnection func(port int)

	mu   sync.Mutex
	lns  []net.Listener
	wg   sync.WaitGroup
	open bool
}

// Start binds the port. Addresses are the bind addresses to listen on; an
// empty list means the wildcard address for both families.
func (l *Listener) Start(addresses []string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open {
		return errors.New("egress: already started")
	}

	targets := addresses
	if len(targets) == 0 {
		targets = []string{""}
	}

	for _, addr := range targets {
		ln, err := net.Listen("tcp", net.JoinHostPort(addr, fmt.Sprint(l.Port)))
		if err != nil {
			l.closeAllLocked()
			return fmt.Errorf("egress: listening on %s port %d: %w", addr, l.Port, err)
		}
		l.lns = append(l.lns, ln)
	}

	for _, ln := range l.lns {
		l.wg.Add(1)
		go func(ln net.Listener) {
			defer l.wg.Done()
			l.serve(ln)
		}(ln)
	}
	l.open = true
	return nil
}

// Close stops the listener.
func (l *Listener) Close() error {
	l.mu.Lock()
	l.closeAllLocked()
	l.open = false
	l.mu.Unlock()
	l.wg.Wait()
	return nil
}

func (l *Listener) closeAllLocked() {
	for _, ln := range l.lns {
		ln.Close()
	}
	l.lns = nil
}

// Addrs reports the bound addresses, which tests need when the port was zero.
func (l *Listener) Addrs() []net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]net.Addr, 0, len(l.lns))
	for _, ln := range l.lns {
		out = append(out, ln.Addr())
	}
	return out
}

func (l *Listener) serve(ln net.Listener) {
	// The banner names the port actually bound, not the one requested. Its
	// entire purpose is to let a client confirm which port it reached, so it
	// has to reflect reality rather than intent.
	port := l.Port
	if ap, err := netip.ParseAddrPort(ln.Addr().String()); err == nil {
		port = int(ap.Port())
	}
	banner := []byte(BannerFor(port))
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if l.OnConnection != nil {
			l.OnConnection(l.Port)
		}
		// Handled inline rather than per-goroutine: the whole interaction is
		// one small write and a close, and spawning a goroutine per connection
		// would hand an attacker a cheap way to multiply work on a
		// single-core host.
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = conn.Write(banner)
		_ = conn.Close()
	}
}

// Set is a group of listeners.
type Set struct {
	listeners []*Listener
}

// Start brings up one listener per port.
func Start(ports []int, addresses []string, log *slog.Logger, onConn func(port int)) (*Set, error) {
	s := &Set{}
	for _, port := range ports {
		l := &Listener{Port: port, Log: log, OnConnection: onConn}
		if err := l.Start(addresses); err != nil {
			s.Close()
			return nil, err
		}
		s.listeners = append(s.listeners, l)
	}
	return s, nil
}

// Close stops every listener.
func (s *Set) Close() error {
	for _, l := range s.listeners {
		l.Close()
	}
	s.listeners = nil
	return nil
}

// Listeners exposes the individual listeners, for tests.
func (s *Set) Listeners() []*Listener { return s.listeners }
