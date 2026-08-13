package ipclass

import (
	"net/netip"
	"testing"
)

func TestOf(t *testing.T) {
	cases := []struct {
		addr string
		want Class
	}{
		// Ordinary public addresses.
		{"1.1.1.1", Global},
		{"201.79.4.56", Global},
		{"2a03:b0c0:3:f0:0:2:ce4c:7000", Global},
		{"2001:db8::1", Global}, // documentation range is still global unicast

		// Carrier-grade NAT, and its boundaries. 100.64.0.0/10 spans
		// 100.64.0.0 to 100.127.255.255; 100.63.x and 100.128.x are public.
		{"100.64.0.0", CGNAT},
		{"100.127.255.255", CGNAT},
		{"100.63.255.255", Global},
		{"100.128.0.0", Global},

		// RFC 1918, including the edges of the awkward /12.
		{"10.0.0.0", Private},
		{"10.255.255.255", Private},
		{"172.16.0.0", Private},
		{"172.31.255.255", Private},
		{"172.15.255.255", Global},
		{"172.32.0.0", Global},
		{"192.168.0.0", Private},
		{"192.168.255.255", Private},
		{"192.167.255.255", Global},

		{"127.0.0.1", Loopback},
		{"127.255.255.255", Loopback},
		{"169.254.1.1", LinkLocal},
		{"0.0.0.0", Unspecified},

		// IPv6 special ranges. Teredo and 6to4 sit inside global unicast, so
		// these assertions are the ones that catch an ordering mistake.
		{"2001::1", Teredo},
		{"2001:0:53aa:64c:2c:8b2f:3f57:fef8", Teredo},
		{"2001:1::1", Global}, // just outside 2001::/32
		{"2002::1", SixToFour},
		{"2002:ffff:ffff::1", SixToFour},
		{"2003::1", Global},

		{"fc00::1", UniqueLocal},
		{"fd00::1", UniqueLocal},
		{"fdff:ffff::1", UniqueLocal},
		{"fe00::1", Global}, // fe00::/8 is not unique-local
		{"fe80::1", LinkLocal},
		{"febf:ffff::1", LinkLocal},
		{"fec0::1", Global}, // deprecated site-local, no longer special
		{"::1", Loopback},
		{"::", Unspecified},
	}

	for _, c := range cases {
		addr := netip.MustParseAddr(c.addr)
		if got := Of(addr); got != c.want {
			t.Errorf("Of(%s) = %q, want %q", c.addr, got, c.want)
		}
	}
}

// A dual-stack listener hands us IPv4-mapped addresses. If those are not
// unmapped before classification, every IPv4 client is reported "global" and
// the CGNAT advice never fires -- which is the single most useful thing the
// classifier says.
func TestOfUnmapsIPv4Mapped(t *testing.T) {
	cases := []struct {
		addr string
		want Class
	}{
		{"::ffff:100.64.0.1", CGNAT},
		{"::ffff:192.168.1.1", Private},
		{"::ffff:127.0.0.1", Loopback},
		{"::ffff:8.8.8.8", Global},
	}
	for _, c := range cases {
		addr := netip.MustParseAddr(c.addr)
		if got := Of(addr); got != c.want {
			t.Errorf("Of(%s) = %q, want %q", c.addr, got, c.want)
		}
	}
}

// A zone-scoped address must classify by its address, not fail to match.
func TestOfStripsZone(t *testing.T) {
	addr := netip.MustParseAddr("fe80::1%eth0")
	if got := Of(addr); got != LinkLocal {
		t.Errorf("Of(fe80::1%%eth0) = %q, want %q", got, LinkLocal)
	}
}

func TestOfInvalid(t *testing.T) {
	if got := Of(netip.Addr{}); got != Unspecified {
		t.Errorf("Of(zero) = %q, want %q", got, Unspecified)
	}
	if got := OfString("not an address"); got != Unspecified {
		t.Errorf("OfString(garbage) = %q, want %q", got, Unspecified)
	}
	if got := OfString("100.64.0.1"); got != CGNAT {
		t.Errorf("OfString(100.64.0.1) = %q, want %q", got, CGNAT)
	}
}

func TestRoutable(t *testing.T) {
	routable := []Class{Global, Teredo, SixToFour}
	notRoutable := []Class{CGNAT, Private, UniqueLocal, Loopback, LinkLocal, Unspecified}

	for _, c := range routable {
		if !c.Routable() {
			t.Errorf("%q should be routable", c)
		}
	}
	for _, c := range notRoutable {
		if c.Routable() {
			t.Errorf("%q should not be routable", c)
		}
	}
}

// Every class must have advice; a client displaying an empty string is worse
// than useless.
func TestAdviceIsAlwaysPresent(t *testing.T) {
	all := []Class{Global, CGNAT, Private, UniqueLocal, Loopback, Teredo,
		SixToFour, LinkLocal, Unspecified}
	for _, c := range all {
		if c.Advice() == "" {
			t.Errorf("class %q has no advice", c)
		}
	}
}
