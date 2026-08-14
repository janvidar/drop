package dropclient

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
)

// LocalPort is how a client detects source-port rewriting for itself, now that
// the server no longer accepts control_port. It is only useful if it really
// reports the port the connection left on, so check it against what the far end
// of that same connection saw.
func TestLocalPortMatchesWhatTheServerObserves(t *testing.T) {
	var observed int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, p, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			t.Errorf("RemoteAddr %q: %v", r.RemoteAddr, err)
		}
		observed, _ = strconv.Atoi(p)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ip": "127.0.0.1", "port": observed, "family": "ipv4", "class": "loopback",
		})
	}))
	defer srv.Close()

	c := New(srv.URL, IPv4, netip.Addr{})
	if _, err := c.Whoami(context.Background()); err != nil {
		t.Fatal(err)
	}

	if c.LocalPort() == 0 {
		t.Fatal("LocalPort() is 0 after a completed request; the capture in DialContext is not wired up")
	}
	// Loopback has no NAT, so these are necessarily the same port.
	if c.LocalPort() != observed {
		t.Errorf("LocalPort() = %d, server observed %d; over loopback these must agree",
			c.LocalPort(), observed)
	}
}
