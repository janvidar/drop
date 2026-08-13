package egress

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startOne(t *testing.T) *Listener {
	t.Helper()
	l := &Listener{Port: 0, Log: discardLog()}
	if err := l.Start([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestBannerFor(t *testing.T) {
	if got := BannerFor(1511); got != "DROP/1 EGRESS 1511\n" {
		t.Errorf("banner = %q", got)
	}
	// A client matches on this prefix; changing it silently breaks every
	// deployed client's egress test.
	if !strings.HasPrefix(BannerFor(411), "DROP/1 EGRESS ") {
		t.Error("the banner prefix must not change")
	}
}

// The point of the whole listener: it speaks first, so a client can tell it
// reached DROP rather than a captive portal that accepted the connection.
func TestListenerSpeaksFirst(t *testing.T) {
	l := startOne(t)
	addr := l.Addrs()[0]
	port := int(netip.MustParseAddrPort(addr.String()).Port())

	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Deliberately send nothing: the server must not be waiting on us.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no banner: %v", err)
	}

	want := BannerFor(port)
	if string(buf[:n]) != want {
		t.Errorf("banner = %q, want %q", buf[:n], want)
	}
}

// The banner names the port actually reached, so a client can detect a
// middlebox that redirected it somewhere else.
func TestBannerNamesTheRealPort(t *testing.T) {
	a := startOne(t)
	b := startOne(t)

	for _, l := range []*Listener{a, b} {
		addr := l.Addrs()[0]
		port := int(netip.MustParseAddrPort(addr.String()).Port())

		conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 128)
		n, _ := conn.Read(buf)
		conn.Close()

		if got := strings.TrimSpace(string(buf[:n])); got != strings.TrimSpace(BannerFor(port)) {
			t.Errorf("port %d: banner = %q", port, got)
		}
	}
	if a.Addrs()[0].String() == b.Addrs()[0].String() {
		t.Fatal("the two listeners should have distinct ports")
	}
}

// The connection closes on its own; a client must not have to time out.
func TestListenerClosesAfterBanner(t *testing.T) {
	l := startOne(t)

	conn, err := net.DialTimeout("tcp", l.Addrs()[0].String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	all, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading to EOF: %v", err)
	}
	if !strings.HasPrefix(string(all), "DROP/1 EGRESS ") {
		t.Errorf("read %q", all)
	}
}

// A client that connects and says nothing, or floods, must not affect the
// listener: it never reads, so there is nothing to exhaust.
func TestListenerIgnoresClientInput(t *testing.T) {
	l := startOne(t)
	addr := l.Addrs()[0].String()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte(strings.Repeat("x", 64*1024)))
	conn.Close()

	// A subsequent connection still gets its banner.
	conn2, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	if _, err := conn2.Read(buf); err != nil {
		t.Fatalf("listener stopped serving: %v", err)
	}
}

func TestSetStartAndClose(t *testing.T) {
	var count atomic.Int64
	set, err := Start([]int{0, 0, 0}, []string{"127.0.0.1"}, discardLog(),
		func(int) { count.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Listeners()) != 3 {
		t.Fatalf("got %d listeners, want 3", len(set.Listeners()))
	}

	for _, l := range set.Listeners() {
		conn, err := net.DialTimeout("tcp", l.Addrs()[0].String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.ReadAll(conn)
		conn.Close()
	}
	if got := count.Load(); got != 3 {
		t.Errorf("counted %d connections, want 3", got)
	}

	addr := set.Listeners()[0].Addrs()[0].String()
	set.Close()

	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Error("the listener should be closed")
	}
}

// A port already in use must fail the whole set rather than leaving a partial
// deployment where some egress ports answer and others do not.
func TestStartFailsAtomically(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	taken := int(netip.MustParseAddrPort(blocker.Addr().String()).Port())

	set, err := Start([]int{0, taken}, []string{"127.0.0.1"}, discardLog(), nil)
	if err == nil {
		set.Close()
		t.Fatal("expected the conflicting port to fail the set")
	}
	if !strings.Contains(err.Error(), "egress") {
		t.Errorf("error should name the component: %v", err)
	}
}

func TestDoubleStartRejected(t *testing.T) {
	l := startOne(t)
	if err := l.Start([]string{"127.0.0.1"}); err == nil {
		t.Error("starting twice should be refused")
	}
}
