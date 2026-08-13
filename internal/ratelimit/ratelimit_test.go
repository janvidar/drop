package ratelimit

import (
	"net/netip"
	"testing"
	"time"
)

func TestKeys(t *testing.T) {
	cases := []struct{ addr, host, prefix string }{
		{"203.0.113.7", "203.0.113.7", "203.0.113.0/24"},
		{"203.0.113.255", "203.0.113.255", "203.0.113.0/24"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		// A dual-stack listener yields mapped addresses; they must aggregate
		// as IPv4 /24, not as IPv6 /64.
		{"::ffff:203.0.113.7", "203.0.113.7", "203.0.113.0/24"},
	}
	for _, c := range cases {
		host, prefix := Keys(netip.MustParseAddr(c.addr))
		if host != c.host || prefix != c.prefix {
			t.Errorf("Keys(%s) = (%q, %q), want (%q, %q)",
				c.addr, host, prefix, c.host, c.prefix)
		}
	}
}

func TestAllowConsumesBurstThenThrottles(t *testing.T) {
	l := New(Config{
		Host:       Rule{Every: time.Minute, Burst: 3},
		Prefix:     Rule{Every: time.Second, Burst: 1000},
		MaxEntries: 100,
	})
	now := time.Now()
	addr := netip.MustParseAddr("203.0.113.7")

	for i := 0; i < 3; i++ {
		if ok, _ := l.AllowAt(now, addr); !ok {
			t.Fatalf("request %d of the burst was denied", i+1)
		}
	}
	ok, wait := l.AllowAt(now, addr)
	if ok {
		t.Fatal("fourth request should have been denied")
	}
	if wait <= 0 || wait > time.Minute {
		t.Errorf("retry-after = %v, want a positive value up to a minute", wait)
	}

	// After the replenish interval, exactly one more should pass.
	later := now.Add(time.Minute)
	if ok, _ := l.AllowAt(later, addr); !ok {
		t.Error("request after replenishment was denied")
	}
	if ok, _ := l.AllowAt(later, addr); ok {
		t.Error("only one token should have replenished")
	}
}

// A client exhausting its own bucket must not consume the prefix budget of its
// neighbours, and vice versa.
func TestPrefixBudgetIsSharedButHostBudgetIsNot(t *testing.T) {
	l := New(Config{
		Host:       Rule{Every: time.Hour, Burst: 2},
		Prefix:     Rule{Every: time.Hour, Burst: 3},
		MaxEntries: 100,
	})
	now := time.Now()
	a := netip.MustParseAddr("203.0.113.7")
	b := netip.MustParseAddr("203.0.113.8")

	// a exhausts its own host bucket after 2.
	for i := 0; i < 2; i++ {
		if ok, _ := l.AllowAt(now, a); !ok {
			t.Fatalf("a request %d denied", i+1)
		}
	}
	if ok, _ := l.AllowAt(now, a); ok {
		t.Fatal("a should be host-limited after 2")
	}

	// b has its own host bucket, but the shared /24 prefix bucket has only one
	// token left, so exactly one of b's requests succeeds.
	if ok, _ := l.AllowAt(now, b); !ok {
		t.Fatal("b's first request should pass on the remaining prefix token")
	}
	if ok, wait := l.AllowAt(now, b); ok {
		t.Error("b should now be prefix-limited")
	} else if wait <= 0 {
		t.Error("prefix limit should report a retry-after")
	}

	// A different /24 is unaffected.
	c := netip.MustParseAddr("203.0.114.1")
	if ok, _ := l.AllowAt(now, c); !ok {
		t.Error("an address in another /24 should not be limited")
	}
}

// A request denied by the prefix bucket must not spend a host token,
// otherwise a client sharing a busy prefix is punished twice for traffic that
// was not its own.
//
// The host rule replenishes so slowly here that it is effectively static, so
// the five successes at the end can only come from tokens the denials left
// alone. The prefix rule replenishes once an hour, which is what lets those
// five requests through one at a time.
func TestPrefixDenialDoesNotConsumeHostTokens(t *testing.T) {
	l := New(Config{
		Host:       Rule{Every: 100 * time.Hour, Burst: 5},
		Prefix:     Rule{Every: time.Hour, Burst: 1},
		MaxEntries: 100,
	})
	now := time.Now()
	a := netip.MustParseAddr("203.0.113.7")
	b := netip.MustParseAddr("203.0.113.8")

	// b drains the single shared prefix token.
	if ok, _ := l.AllowAt(now, b); !ok {
		t.Fatal("b's first request should pass")
	}
	// a is now denied by the prefix bucket, repeatedly.
	for i := 0; i < 4; i++ {
		if ok, _ := l.AllowAt(now, a); ok {
			t.Fatalf("a request %d should be prefix-denied", i+1)
		}
	}

	for i := 1; i <= 5; i++ {
		at := now.Add(time.Duration(i) * time.Hour)
		if ok, _ := l.AllowAt(at, a); !ok {
			t.Fatalf("a lost host tokens to prefix-denied requests (failed at %d of 5)", i)
		}
	}
}

// The mirror image: a request denied by the host bucket must not spend a
// prefix token, or one noisy address would exhaust the budget of everyone
// sharing its /24.
func TestHostDenialDoesNotConsumePrefixTokens(t *testing.T) {
	const prefixBurst = 10
	l := New(Config{
		Host:       Rule{Every: 100 * time.Hour, Burst: 1},
		Prefix:     Rule{Every: 100 * time.Hour, Burst: prefixBurst},
		MaxEntries: 100,
	})
	now := time.Now()
	noisy := netip.MustParseAddr("203.0.113.1")

	if ok, _ := l.AllowAt(now, noisy); !ok {
		t.Fatal("the noisy address's first request should pass")
	}
	for i := 0; i < 20; i++ {
		if ok, _ := l.AllowAt(now, noisy); ok {
			t.Fatalf("noisy request %d should be host-denied", i+2)
		}
	}

	// Each neighbour has its own untouched host bucket, so every success or
	// failure below is decided purely by the shared prefix budget.
	success := 0
	for i := 2; i <= 30; i++ {
		addr := netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
		if ok, _ := l.AllowAt(now, addr); ok {
			success++
		}
	}
	if want := prefixBurst - 1; success != want {
		t.Errorf("%d neighbours got through, want %d: the host-denied requests "+
			"consumed prefix tokens", success, want)
	}
}

func TestIPv6AggregatesPerSlash64(t *testing.T) {
	l := New(Config{
		Host:       Rule{Every: time.Hour, Burst: 1},
		Prefix:     Rule{Every: time.Hour, Burst: 2},
		MaxEntries: 100,
	})
	now := time.Now()

	// Three distinct addresses in one /64 -- the trivial evasion an
	// address-only limiter would miss.
	for i, s := range []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"} {
		ok, _ := l.AllowAt(now, netip.MustParseAddr(s))
		want := i < 2
		if ok != want {
			t.Errorf("%s: allowed = %v, want %v", s, ok, want)
		}
	}

	// A different /64 has its own budget.
	if ok, _ := l.AllowAt(now, netip.MustParseAddr("2001:db8:0:1::1")); !ok {
		t.Error("a different /64 should have its own budget")
	}
}

func TestEvictionBoundsMemory(t *testing.T) {
	const max = 64
	l := New(Config{
		Host:       Rule{Every: time.Second, Burst: 1},
		Prefix:     Rule{Every: time.Second, Burst: 1},
		MaxEntries: max,
	})
	now := time.Now()

	for i := 0; i < 1000; i++ {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		l.AllowAt(now, addr)
	}
	if got := l.Len(); got > max {
		t.Errorf("bucket table grew to %d, above the %d cap", got, max)
	}
}

func TestZeroBurstDeniesEverything(t *testing.T) {
	l := New(Config{
		Host:       Rule{Every: time.Second, Burst: 0},
		Prefix:     Rule{Every: time.Second, Burst: 100},
		MaxEntries: 10,
	})
	ok, wait := l.AllowAt(time.Now(), netip.MustParseAddr("203.0.113.7"))
	if ok {
		t.Error("a zero burst must deny")
	}
	if wait <= 0 {
		t.Error("a denial must report a retry-after")
	}
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig(12)
	if c.Host.Every != 5*time.Minute {
		t.Errorf("host interval = %v, want 5m for 12/hour", c.Host.Every)
	}
	if c.Prefix.Every >= c.Host.Every {
		t.Error("the prefix bucket should replenish faster than a single host's")
	}
	if c.Prefix.Burst <= c.Host.Burst {
		t.Error("the prefix bucket should allow a larger burst than a single host")
	}
	// Degenerate input must not produce a division by zero or an infinite rate.
	if got := DefaultConfig(0); got.Host.Every != time.Hour {
		t.Errorf("DefaultConfig(0) host interval = %v, want 1h", got.Host.Every)
	}
}

func TestConcurrentUse(t *testing.T) {
	l := New(DefaultConfig(3600))
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				l.Allow(netip.AddrFrom4([4]byte{10, byte(i), byte(j), 1}))
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
