package natdisc

import (
	"net"
	"net/netip"
	"testing"
)

// The bug this guards against was found on a live dual-address host: without a
// pinned source, the kernel picks a different address for each of the mapping
// tests -- RFC 6724 prefers the address sharing the longest prefix with the
// destination, and the mapping tests aim at two addresses in the server's own
// subnet. The resulting "the mapped address changed" reads as address-dependent
// mapping on a machine with no NAT at all.
func TestListenPinsASourceAddress(t *testing.T) {
	// Two loopback addresses stand in for two addresses of one family.
	primary := netip.MustParseAddrPort("127.0.0.1:3478")
	alternate := netip.MustParseAddrPort("127.0.0.2:3479")

	conn, err := listen(Config{Primary: primary})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	bound := localAddrPort(conn)
	if !bound.Addr().IsValid() || bound.Addr().IsUnspecified() {
		t.Fatalf("socket bound to %v; an unspecified source lets the kernel "+
			"choose per destination and breaks the mapping classification", bound)
	}

	// The same socket must present that one address to both destinations.
	for _, dst := range []netip.AddrPort{primary, alternate} {
		if _, err := conn.WriteToUDP([]byte("x"), net.UDPAddrFromAddrPort(dst)); err != nil {
			t.Fatalf("writing to %v: %v", dst, err)
		}
	}
	if after := localAddrPort(conn); after != bound {
		t.Errorf("local address changed from %v to %v between destinations", bound, after)
	}
}

// An explicitly configured source must be honoured rather than rediscovered.
func TestListenHonoursConfiguredLocalAddr(t *testing.T) {
	conn, err := listen(Config{
		Primary:   netip.MustParseAddrPort("127.0.0.1:3478"),
		LocalAddr: netip.MustParseAddr("127.0.0.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if got := localAddrPort(conn).Addr(); got != netip.MustParseAddr("127.0.0.2") {
		t.Errorf("bound to %v, want the configured 127.0.0.2", got)
	}
}

func TestPreferredSource(t *testing.T) {
	got := preferredSource("udp4", netip.MustParseAddrPort("127.0.0.1:9"))
	if !got.IsValid() {
		t.Fatal("no preferred source found for a loopback destination")
	}
	if !got.IsLoopback() {
		t.Errorf("preferred source for a loopback destination = %v", got)
	}
}

func TestHolePunchLikely(t *testing.T) {
	cases := []struct {
		mapping, filtering Behaviour
		want               bool
	}{
		{NoNAT, EndpointIndependent, true},
		{EndpointIndependent, EndpointIndependent, true},
		{EndpointIndependent, AddressDependent, true},
		{EndpointIndependent, AddressAndPortDependent, false},
		{AddressDependent, EndpointIndependent, false},
		{AddressAndPortDependent, EndpointIndependent, false},
		{Blocked, Blocked, false},
	}
	for _, c := range cases {
		got := Result{Mapping: c.mapping, Filtering: c.filtering}.HolePunchLikely()
		if got != c.want {
			t.Errorf("%s/%s: HolePunchLikely = %v, want %v",
				c.mapping, c.filtering, got, c.want)
		}
	}
}

func TestSummaryAlwaysPresent(t *testing.T) {
	for _, r := range []Result{
		{Mapping: Blocked},
		{Mapping: NoNAT},
		{Mapping: EndpointIndependent, Filtering: EndpointIndependent},
		{Mapping: AddressAndPortDependent, Filtering: AddressAndPortDependent},
		{Mapping: Unknown, Filtering: Unknown},
	} {
		if Result.Summary(r) == "" {
			t.Errorf("mapping %q has no summary", r.Mapping)
		}
	}
}
