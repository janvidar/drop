package session

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func newManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(testSecret, time.Minute, 100)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNewManagerRejectsWeakSecret(t *testing.T) {
	if _, err := NewManager([]byte("short"), time.Minute, 10); err == nil {
		t.Error("a short secret must be rejected")
	}
	if _, err := NewManager(testSecret, 0, 10); err == nil {
		t.Error("a non-positive ttl must be rejected")
	}
}

func TestIssueAndParseRoundTrip(t *testing.T) {
	m := newManager(t)
	addr := netip.MustParseAddr("203.0.113.7")

	s, err := m.Issue(addr)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID == "" || s.STUNPassword == "" {
		t.Fatal("session is missing an id or credentials")
	}
	if s.STUNUsername != s.ID {
		t.Error("the STUN username should be the session id")
	}

	got, err := m.Parse(s.ID, addr)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Addr != addr {
		t.Errorf("addr = %v, want %v", got.Addr, addr)
	}
	if got.STUNPassword != s.STUNPassword {
		t.Error("the STUN password must be reproducible from the id alone")
	}
}

// Two sessions issued for the same address in the same instant must differ,
// or a client checking twice would collide with itself.
func TestIssueIsUnique(t *testing.T) {
	m := newManager(t)
	addr := netip.MustParseAddr("203.0.113.7")

	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		s, err := m.Issue(addr)
		if err != nil {
			t.Fatal(err)
		}
		if seen[s.ID] {
			t.Fatalf("duplicate session id at iteration %d", i)
		}
		seen[s.ID] = true
	}
}

// The core security property of the session token: it is only usable from the
// address it was issued to. Otherwise a leaked identifier lets someone have a
// third party's address probed.
func TestParseRejectsDifferentSourceAddress(t *testing.T) {
	m := newManager(t)
	issued := netip.MustParseAddr("203.0.113.7")
	other := netip.MustParseAddr("203.0.113.8")

	s, err := m.Issue(issued)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Parse(s.ID, other); !errors.Is(err, ErrWrongSource) {
		t.Fatalf("err = %v, want ErrWrongSource", err)
	}
	// Same address in the other family is still a different address.
	if _, err := m.Parse(s.ID, netip.MustParseAddr("2001:db8::1")); !errors.Is(err, ErrWrongSource) {
		t.Fatalf("err = %v, want ErrWrongSource", err)
	}
}

// A dual-stack listener presents an IPv4 peer as ::ffff:a.b.c.d. The session
// must still match, or every v4 client on a dual-stack socket breaks.
func TestParseAcceptsIPv4MappedForm(t *testing.T) {
	m := newManager(t)
	s, err := m.Issue(netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Parse(s.ID, netip.MustParseAddr("::ffff:203.0.113.7")); err != nil {
		t.Fatalf("mapped form rejected: %v", err)
	}
}

func TestParseRejectsTampering(t *testing.T) {
	m := newManager(t)
	addr := netip.MustParseAddr("203.0.113.7")
	s, err := m.Issue(addr)
	if err != nil {
		t.Fatal(err)
	}

	payload, mac, _ := strings.Cut(s.ID, ".")

	cases := []struct {
		name string
		id   string
		want error
	}{
		{"empty", "", ErrMalformed},
		{"no separator", payload + mac, ErrMalformed},
		{"garbage payload", "!!!." + mac, ErrMalformed},
		{"truncated payload", payload[:8] + "." + mac, ErrMalformed},
		{"garbage mac", payload + ".!!!", ErrMalformed},
		{"wrong mac", payload + "." + flipLast(mac), ErrBadMAC},
		{"payload edited", flipLast(payload) + "." + mac, ErrBadMAC},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := m.Parse(c.id, addr)
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// A token signed with a different secret must not validate. This is what stops
// one deployment's tokens working against another.
func TestParseRejectsForeignSecret(t *testing.T) {
	m1 := newManager(t)
	other, err := NewManager([]byte("ffffffffffffffffffffffffffffffff"), time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("203.0.113.7")

	s, err := other.Issue(addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m1.Parse(s.ID, addr); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("err = %v, want ErrBadMAC", err)
	}
}

func TestParseRejectsExpired(t *testing.T) {
	m := newManager(t)
	base := time.Now()
	m.now = func() time.Time { return base }

	addr := netip.MustParseAddr("203.0.113.7")
	s, err := m.Issue(addr)
	if err != nil {
		t.Fatal(err)
	}

	m.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := m.Parse(s.ID, addr); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

// Unpadded base64 of a 32-byte value has two bits in its last character that
// carry no data, so a permissive decoder accepts several spellings of the same
// value. With single-use tracked by identifier string, each accepted spelling
// would buy another run of the inbound test -- a single-use and rate-limit
// bypass costing an attacker one character.
func TestSingleUseSurvivesEncodingVariants(t *testing.T) {
	m := newManager(t)
	addr := netip.MustParseAddr("203.0.113.7")
	s, err := m.Issue(addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(s); err != nil {
		t.Fatal(err)
	}

	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	payloadB64, macB64, _ := strings.Cut(s.ID, ".")

	tried := 0
	for _, c := range alphabet {
		for _, variant := range []string{
			payloadB64[:len(payloadB64)-1] + string(c) + "." + macB64,
			payloadB64 + "." + macB64[:len(macB64)-1] + string(c),
		} {
			if variant == s.ID {
				continue
			}
			parsed, err := m.Parse(variant, addr)
			if err != nil {
				continue // rejected outright, which is the ideal outcome
			}
			tried++
			// It validated, so it must be recognised as the same session.
			if err := m.Consume(parsed); !errors.Is(err, ErrAlreadyRan) {
				t.Fatalf("variant %q was accepted as a fresh session (err = %v): "+
					"single use can be bypassed by respelling the identifier",
					variant[len(variant)-8:], err)
			}
		}
	}
	t.Logf("%d encoding variants validated; all were recognised as the same session", tried)
}

func TestConsumeIsSingleUse(t *testing.T) {
	m := newManager(t)
	s, err := m.Issue(netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Consume(s); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if err := m.Consume(s); !errors.Is(err, ErrAlreadyRan) {
		t.Fatalf("second Consume: err = %v, want ErrAlreadyRan", err)
	}
	if m.Active() != 1 {
		t.Errorf("Active = %d, want 1", m.Active())
	}
}

// Flooding the table must not evict consumed sessions: that would turn
// single-use into unlimited-use for an attacker willing to make noise.
func TestConsumeRefusesRatherThanEvicting(t *testing.T) {
	m, err := NewManager(testSecret, time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	victim, err := m.Issue(netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(victim); err != nil {
		t.Fatal(err)
	}

	// Fill the remaining capacity.
	for i := 0; i < 10; i++ {
		s, err := m.Issue(netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 100)}))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Consume(s); err != nil && !errors.Is(err, ErrTooMany) {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// The already-consumed session must still be refused, not forgotten.
	if err := m.Consume(victim); !errors.Is(err, ErrAlreadyRan) {
		t.Fatalf("replay after flooding: err = %v, want ErrAlreadyRan", err)
	}
}

// Expired entries must be reclaimed, or the table fills with dead sessions and
// legitimate clients start getting ErrTooMany.
func TestConsumeSweepsExpiredEntries(t *testing.T) {
	m, err := NewManager(testSecret, time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	m.now = func() time.Time { return base }

	for i := 0; i < 4; i++ {
		s, err := m.Issue(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Consume(s); err != nil {
			t.Fatalf("Consume %d: %v", i, err)
		}
	}
	if m.Active() != 4 {
		t.Fatalf("Active = %d, want 4", m.Active())
	}

	m.now = func() time.Time { return base.Add(2 * time.Minute) }
	fresh, err := m.Issue(netip.MustParseAddr("203.0.113.99"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(fresh); err != nil {
		t.Fatalf("Consume after expiry should succeed, got %v", err)
	}
	if m.Active() != 1 {
		t.Errorf("Active = %d, want 1 after the sweep", m.Active())
	}
}

func TestNonceIsBoundToSessionProtocolAndPort(t *testing.T) {
	m := newManager(t)
	a, err := m.Issue(netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Issue(netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}

	base := m.Nonce(a, "tcp", 1511)
	if base == "" {
		t.Fatal("empty nonce")
	}
	if m.Nonce(a, "tcp", 1511) != base {
		t.Error("the nonce must be reproducible for the same inputs")
	}
	// A nonce seen on one port must say nothing about another port, another
	// protocol, or another session.
	if m.Nonce(a, "tcp", 1512) == base {
		t.Error("nonce is not bound to the port")
	}
	if m.Nonce(a, "udp", 1511) == base {
		t.Error("nonce is not bound to the protocol")
	}
	if m.Nonce(b, "tcp", 1511) == base {
		t.Error("nonce is not bound to the session")
	}
}

func TestVerifyNonce(t *testing.T) {
	m := newManager(t)
	s, err := m.Issue(netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}
	good := m.Nonce(s, "tcp", 1511)

	if !m.VerifyNonce(s, "tcp", 1511, good) {
		t.Error("the correct nonce must verify")
	}
	for _, bad := range []string{"", good + "x", good[:len(good)-1], strings.ToUpper(good)} {
		if m.VerifyNonce(s, "tcp", 1511, bad) {
			t.Errorf("nonce %q must not verify", bad)
		}
	}
}

// The several uses of the one secret must not be interchangeable.
func TestDomainSeparation(t *testing.T) {
	m := newManager(t)
	s, err := m.Issue(netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}
	if s.STUNPassword == m.Nonce(s, "tcp", 1511) {
		t.Error("the STUN password and a nonce must not collide")
	}
	if strings.Contains(s.ID, s.STUNPassword) {
		t.Error("the session id must not embed the password")
	}
}

// flipLast changes the last character of a base64 field to a different value.
//
// The replacement must itself be a valid strict encoding, or the decoder
// rejects it as malformed before the MAC is ever checked and the caller sees
// the wrong error. Both 'A' (index 0) and 'Q' (index 16) have zero in the two
// low bits, which is what strict unpadded base64 requires of a final character
// here.
func flipLast(s string) string {
	if s == "" {
		return "x"
	}
	repl := byte('A')
	if s[len(s)-1] == 'A' {
		repl = 'Q'
	}
	return s[:len(s)-1] + string(repl)
}
