// Package session issues and validates the short-lived authorisations that
// let a client have its own address probed.
//
// Sessions are almost entirely stateless. The session identifier carries its
// own expiry and the address it was issued to, authenticated by a MAC over a
// per-server secret; the TCP challenge nonce and the STUN short-term password
// are derived from the same secret. That means a probe needs no lookup, a
// restart does not strand clients mid-check, and memory does not grow with
// traffic -- which matters on a host with 458 MB of RAM.
//
// The one piece of real state is the set of sessions that have already run
// their inbound test, because "single use" cannot be derived from a token.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Errors returned by Parse and Consume. Callers map these onto HTTP statuses,
// so they are distinguishable rather than a single opaque failure.
var (
	ErrMalformed   = errors.New("malformed session id")
	ErrBadMAC      = errors.New("session id failed authentication")
	ErrExpired     = errors.New("session expired")
	ErrWrongSource = errors.New("session belongs to a different source address")
	ErrAlreadyRan  = errors.New("session already ran its inbound test")
	ErrTooMany     = errors.New("too many concurrent sessions")
)

// enc is the encoding for every token in this package: URL-safe and
// unpadded, so tokens are safe in a path segment and in a single ASCII line.
var enc = base64.RawURLEncoding

// Session is an issued authorisation.
type Session struct {
	ID string
	// Addr is the address the session was issued to, and the only address it
	// may ever cause a probe to be sent to.
	Addr    netip.Addr
	Expires time.Time

	// STUNUsername and STUNPassword are RFC 8489 short-term credentials,
	// scoped to this session.
	STUNUsername string
	STUNPassword string
}

// Manager issues and validates sessions.
type Manager struct {
	secret []byte
	ttl    time.Duration
	max    int
	now    func() time.Time

	mu   sync.Mutex
	used map[string]time.Time // session id -> when it ran its inbound test
}

// NewManager returns a Manager. The secret must be at least 32 bytes and is
// normally read from the state directory so that it survives restarts.
func NewManager(secret []byte, ttl time.Duration, max int) (*Manager, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("session secret must be at least 32 bytes, got %d", len(secret))
	}
	if ttl <= 0 {
		return nil, errors.New("session ttl must be positive")
	}
	if max < 1 {
		max = 4096
	}
	return &Manager{
		secret: append([]byte(nil), secret...),
		ttl:    ttl,
		max:    max,
		now:    time.Now,
		used:   map[string]time.Time{},
	}, nil
}

// Issue mints a session for addr.
//
// The identifier is `<payload>.<mac>`, where payload carries the expiry, the
// address family and the address itself. Everything the server needs to
// validate a later request is therefore in the token, and an attacker cannot
// forge one without the secret.
func (m *Manager) Issue(addr netip.Addr) (Session, error) {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return Session{}, errors.New("invalid address")
	}

	now := m.now()
	expires := now.Add(m.ttl)

	// 8 bytes expiry, 16 bytes address (v4 left-padded), 8 bytes of freshness
	// so that two sessions for the same address in the same second differ.
	payload := make([]byte, 0, 32)
	payload = binary.BigEndian.AppendUint64(payload, uint64(expires.Unix()))
	a16 := addr.As16()
	payload = append(payload, a16[:]...)
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return Session{}, fmt.Errorf("generating session nonce: %w", err)
	}
	payload = append(payload, nonce...)

	id := enc.EncodeToString(payload) + "." + enc.EncodeToString(m.mac("sid", payload))

	return Session{
		ID:           id,
		Addr:         addr,
		Expires:      expires,
		STUNUsername: id,
		STUNPassword: m.derive("stun-password", id),
	}, nil
}

// Parse validates a session identifier and checks it against the address the
// request actually came from.
//
// The source check is what stops a stolen or leaked session identifier from
// being usable to have someone else's address probed, and it is also what
// catches a client whose address changed mid-flow -- whose results would be
// meaningless and possibly aimed at a stranger.
func (m *Manager) Parse(id string, from netip.Addr) (Session, error) {
	from = from.Unmap().WithZone("")

	payloadB64, macB64, ok := strings.Cut(id, ".")
	if !ok {
		return Session{}, ErrMalformed
	}
	payload, err := enc.DecodeString(payloadB64)
	if err != nil || len(payload) != 32 {
		return Session{}, ErrMalformed
	}
	gotMAC, err := enc.DecodeString(macB64)
	if err != nil {
		return Session{}, ErrMalformed
	}
	if !hmac.Equal(gotMAC, m.mac("sid", payload)) {
		return Session{}, ErrBadMAC
	}

	expires := time.Unix(int64(binary.BigEndian.Uint64(payload[:8])), 0)
	if m.now().After(expires) {
		return Session{}, ErrExpired
	}

	var a16 [16]byte
	copy(a16[:], payload[8:24])
	addr := netip.AddrFrom16(a16).Unmap()

	if addr != from {
		return Session{}, ErrWrongSource
	}

	return Session{
		ID:           id,
		Addr:         addr,
		Expires:      expires,
		STUNUsername: id,
		STUNPassword: m.derive("stun-password", id),
	}, nil
}

// Consume marks a session's inbound test as run, and reports ErrAlreadyRan on
// a second attempt. This is the only mutable state in the package.
func (m *Manager) Consume(s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sweepLocked()

	if _, seen := m.used[s.ID]; seen {
		return ErrAlreadyRan
	}
	if len(m.used) >= m.max {
		// Refusing here is deliberate. Evicting an entry to make room would
		// let an attacker recycle a consumed session by flooding the table,
		// turning single-use into unlimited-use.
		return ErrTooMany
	}
	m.used[s.ID] = s.Expires
	return nil
}

// sweepLocked drops entries whose sessions have expired. An expired session
// cannot be replayed anyway, since Parse rejects it first.
func (m *Manager) sweepLocked() {
	now := m.now()
	for id, expires := range m.used {
		if now.After(expires) {
			delete(m.used, id)
		}
	}
}

// Active reports how many consumed sessions are being tracked, for metrics.
func (m *Manager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.used)
}

// Nonce derives the challenge value for one probe.
//
// It is bound to the session, the protocol and the port, so a nonce observed
// on one port proves nothing about another, and it needs no storage. An
// attacker who sees a nonce learns nothing that lets them predict the next.
func (m *Manager) Nonce(s Session, proto string, port int) string {
	return m.derive("nonce", fmt.Sprintf("%s|%s|%d", s.ID, proto, port))
}

// VerifyNonce compares a returned nonce in constant time.
func (m *Manager) VerifyNonce(s Session, proto string, port int, got string) bool {
	want := m.Nonce(s, proto, port)
	return hmac.Equal([]byte(got), []byte(want))
}

func (m *Manager) mac(domain string, msg []byte) []byte {
	h := hmac.New(sha256.New, m.secret)
	// The domain separator keeps the several uses of one secret from being
	// interchangeable: a session MAC must never be usable as a nonce.
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(msg)
	return h.Sum(nil)
}

func (m *Manager) derive(domain, msg string) string {
	// 128 bits is ample for a value that lives for seconds and is single-use,
	// and it keeps the challenge line comfortably short.
	return enc.EncodeToString(m.mac(domain, []byte(msg))[:16])
}
