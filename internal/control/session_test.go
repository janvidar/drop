package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"quickdc.org/drop/internal/config"
	"quickdc.org/drop/internal/probe"
	"quickdc.org/drop/internal/stun"
)

// loopbackConfig probes from and to 127.0.0.1, so the whole session flow can
// run end to end against a real listener without any public address.
func loopbackConfig() config.Config {
	c := config.Default()
	c.Server.Name = "localhost"
	c.Server.AbuseContact = "abuse@example.org"
	c.Control.Hostnames = []string{"localhost"}
	c.Limits.MinPort = 1 // loopback test listeners get ephemeral high ports anyway
	c.Limits.ProbeTimeout = config.Duration{Duration: 2 * time.Second}
	c.STUN = map[string]config.Family{
		"ipv4": {
			PrimaryBind:      "127.0.0.1",
			PrimaryAdvertise: "198.51.100.10",
			PrimaryPort:      3478,
		},
	}
	if err := c.Validate(); err != nil {
		panic(err)
	}
	return c
}

func postJSON(t *testing.T, h http.Handler, target, remoteAddr string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = strings.NewReader(string(buf))
	}
	req := httptest.NewRequest("POST", target, r)
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func openSession(t *testing.T, h http.Handler, remoteAddr string) SessionResponse {
	t.Helper()
	rec := postJSON(t, h, "/v1/session", remoteAddr, SessionRequest{Version: 1, Client: "test"})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/session: status %d, body %s", rec.Code, rec.Body)
	}
	var resp SessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// dcClient stands in for a conforming DC client's listening port.
func dcClient(t *testing.T, answer bool) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 256)
				n, err := conn.Read(buf)
				if err != nil || !answer {
					return
				}
				line := strings.TrimRight(string(buf[:n]), "\r\n")
				nonce, ok := strings.CutPrefix(line, "DROP/1 CHALLENGE ")
				if !ok {
					return
				}
				fmt.Fprintf(conn, "DROP/1 RESPONSE %s\n", nonce)
			}()
		}
	}()

	return int(netip.MustParseAddrPort(ln.Addr().String()).Port())
}

func TestSessionCreate(t *testing.T) {
	s := newTestServerWith(t, loopbackConfig())
	resp := openSession(t, s.Handler(), "127.0.0.1:51343")

	if resp.SessionID == "" {
		t.Fatal("no session id")
	}
	if resp.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d", resp.ExpiresIn)
	}
	if resp.Observed.IP != "127.0.0.1" || resp.Observed.Port != 51343 {
		t.Errorf("observed = %+v", resp.Observed)
	}
	if resp.Creds == nil || resp.Creds.Password == "" {
		t.Error("STUN credentials should be issued")
	}
	if resp.STUN == nil || resp.STUN.Primary == nil {
		t.Fatal("STUN endpoints should be advertised")
	}
	// The advertised address, never the bound one.
	if resp.STUN.Primary.IPv4 != "198.51.100.10" {
		t.Errorf("primary = %q, want the advertised address", resp.STUN.Primary.IPv4)
	}
}

// The whole point of the service, end to end: open a session, have the server
// dial back to a listening client, and get "open".
func TestInboundProbeOpen(t *testing.T) {
	s := newTestServerWith(t, loopbackConfig())
	h := s.Handler()
	port := dcClient(t, true)

	sess := openSession(t, h, "127.0.0.1:51343")
	rec := postJSON(t, h, "/v1/session/"+sess.SessionID+"/inbound", "127.0.0.1:51343",
		InboundRequest{TCP: []int{port}})

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var resp InboundResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.TCP) != 1 {
		t.Fatalf("got %d tcp results, want 1", len(resp.TCP))
	}
	if resp.TCP[0].Verdict != probe.Open {
		t.Errorf("verdict = %q (%s), want open", resp.TCP[0].Verdict, resp.TCP[0].Detail)
	}
	if resp.TCP[0].Port != port {
		t.Errorf("port = %d, want %d", resp.TCP[0].Port, port)
	}
}

// A listener that does not answer the challenge is not the client that asked.
func TestInboundProbeOccupied(t *testing.T) {
	s := newTestServerWith(t, loopbackConfig())
	h := s.Handler()
	port := dcClient(t, false)

	sess := openSession(t, h, "127.0.0.1:51343")
	rec := postJSON(t, h, "/v1/session/"+sess.SessionID+"/inbound", "127.0.0.1:51343",
		InboundRequest{TCP: []int{port}})

	var resp InboundResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TCP[0].Verdict == probe.Open {
		t.Fatal("a listener that never answers must not be reported open")
	}
}

// Single use: a second inbound test on one session must be refused, or the
// per-session rate limit means nothing.
func TestInboundIsSingleUse(t *testing.T) {
	s := newTestServerWith(t, loopbackConfig())
	h := s.Handler()
	port := dcClient(t, true)

	sess := openSession(t, h, "127.0.0.1:51343")
	path := "/v1/session/" + sess.SessionID + "/inbound"
	body := InboundRequest{TCP: []int{port}}

	if rec := postJSON(t, h, path, "127.0.0.1:51343", body); rec.Code != http.StatusOK {
		t.Fatalf("first inbound: status %d", rec.Code)
	}
	rec := postJSON(t, h, path, "127.0.0.1:51343", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second inbound: status %d, want 409", rec.Code)
	}
	var doc ErrorDoc
	json.Unmarshal(rec.Body.Bytes(), &doc)
	if doc.Error != ErrAlreadyRan {
		t.Errorf("error = %q, want %q", doc.Error, ErrAlreadyRan)
	}
}

// The security boundary: a session is usable only from the address it was
// issued to. Otherwise a leaked identifier probes a third party.
func TestInboundRejectsDifferentSourceAddress(t *testing.T) {
	s := newTestServerWith(t, loopbackConfig())
	h := s.Handler()

	sess := openSession(t, h, "127.0.0.1:51343")
	rec := postJSON(t, h, "/v1/session/"+sess.SessionID+"/inbound", "127.0.0.2:51343",
		InboundRequest{TCP: []int{9999}})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	var doc ErrorDoc
	json.Unmarshal(rec.Body.Bytes(), &doc)
	if doc.Error != ErrWrongSource {
		t.Errorf("error = %q, want %q", doc.Error, ErrWrongSource)
	}
}

func TestInboundRejectsUnknownSession(t *testing.T) {
	s := newTestServerWith(t, loopbackConfig())
	h := s.Handler()

	for _, id := range []string{"nonsense", "a.b", strings.Repeat("x", 200)} {
		rec := postJSON(t, h, "/v1/session/"+id+"/inbound", "127.0.0.1:51343",
			InboundRequest{TCP: []int{9999}})
		if rec.Code != http.StatusNotFound {
			t.Errorf("session %q: status %d, want 404", truncate(id), rec.Code)
		}
	}
}

func TestInboundPortValidation(t *testing.T) {
	cfg := loopbackConfig()
	cfg.Limits.MinPort = 1024
	cfg.Limits.MaxPortsPerTest = 4
	s := newTestServerWith(t, cfg)
	h := s.Handler()

	cases := []struct {
		name     string
		req      InboundRequest
		wantCode int
		wantErr  string
	}{
		{"below the floor", InboundRequest{TCP: []int{22}}, http.StatusUnprocessableEntity, ErrPortRange},
		{"port zero", InboundRequest{TCP: []int{0}}, http.StatusUnprocessableEntity, ErrPortRange},
		{"above range", InboundRequest{TCP: []int{70000}}, http.StatusUnprocessableEntity, ErrPortRange},
		{"negative", InboundRequest{TCP: []int{-1}}, http.StatusUnprocessableEntity, ErrPortRange},
		{"too many", InboundRequest{TCP: []int{2000, 2001, 2002, 2003, 2004}}, http.StatusUnprocessableEntity, ErrTooManyPorts},
		{"none at all", InboundRequest{}, http.StatusBadRequest, ErrMalformed},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A distinct source per subtest: sessions are deliberately scarce
			// per address, and this test is about port validation, not about
			// the rate limiter.
			from := fmt.Sprintf("127.0.0.%d:51343", i+1)
			sess := openSession(t, h, from)
			rec := postJSON(t, h, "/v1/session/"+sess.SessionID+"/inbound", from, c.req)
			if rec.Code != c.wantCode {
				t.Fatalf("status %d, want %d (body %s)", rec.Code, c.wantCode, rec.Body)
			}
			var doc ErrorDoc
			json.Unmarshal(rec.Body.Bytes(), &doc)
			if doc.Error != c.wantErr {
				t.Errorf("error = %q, want %q", doc.Error, c.wantErr)
			}
		})
	}
}

// A rejected request must not consume the session, or a client that fat-fingers
// a port has to wait out the rate limit before retrying.
func TestRejectedRequestDoesNotConsumeSession(t *testing.T) {
	cfg := loopbackConfig()
	cfg.Limits.MinPort = 1024
	s := newTestServerWith(t, cfg)
	h := s.Handler()
	port := dcClient(t, true)

	sess := openSession(t, h, "127.0.0.1:51343")
	path := "/v1/session/" + sess.SessionID + "/inbound"

	if rec := postJSON(t, h, path, "127.0.0.1:51343", InboundRequest{TCP: []int{22}}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected the bad port to be rejected, got %d", rec.Code)
	}
	rec := postJSON(t, h, path, "127.0.0.1:51343", InboundRequest{TCP: []int{port}})
	if rec.Code != http.StatusOK {
		t.Fatalf("retry after a rejected request: status %d, body %s", rec.Code, rec.Body)
	}
}

// The field is deprecated but must still decode: the decoder rejects unknown
// fields, so an older client that sends it would otherwise get a 400 rather
// than a check.
func TestInboundStillAcceptsTheDeprecatedControlPort(t *testing.T) {
	s := newTestServerWith(t, loopbackConfig())
	h := s.Handler()
	port := dcClient(t, true)

	sess := openSession(t, h, "127.0.0.1:51343")

	// 51344 deliberately differs from the observed 51343: that inequality is
	// exactly what the old code turned into a note.
	body := fmt.Sprintf(`{"tcp":[%d],"control_port":51344}`, port)
	req := httptest.NewRequest("POST", "/v1/session/"+sess.SessionID+"/inbound",
		strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:51343"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; a deprecated field must not fail the request", rec.Code)
	}

	var resp InboundResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	// Ignored, not acted on. The port deliberately differs from the observed
	// one, which under the old behaviour produced a NAT-rewriting note.
	// Ignored, not acted on. Matched on the specific wording the old
	// behaviour produced -- "rewriting" alone also appears in the
	// private-address note that a loopback test address legitimately raises.
	for _, note := range resp.Notes {
		if strings.Contains(note, "rewriting TCP source ports") ||
			strings.Contains(note, "left your machine on port") {
			t.Errorf("control_port was acted on: %q", note)
		}
	}
}

func TestInboundRejectsUnknownFields(t *testing.T) {
	s := newTestServerWith(t, loopbackConfig())
	h := s.Handler()
	sess := openSession(t, h, "127.0.0.1:51343")

	req := httptest.NewRequest("POST", "/v1/session/"+sess.SessionID+"/inbound",
		strings.NewReader(`{"tcp":[2000],"target_ip":"198.51.100.99"}`))
	req.RemoteAddr = "127.0.0.1:51343"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Not merely ignored: a client that thinks it can name a target must be
	// told plainly that it cannot.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for an unknown field", rec.Code)
	}
}

// The UDP probe end to end: the server sends an authenticated Binding Request
// from an unsolicited source, and the stand-in client answers it.
func TestInboundUDPOpen(t *testing.T) {
	s := newTestServerWith(t, loopbackConfig())
	h := s.Handler()

	sess := openSession(t, h, "127.0.0.1:51343")
	port := udpClient(t, sess.Creds.Password)

	rec := postJSON(t, h, "/v1/session/"+sess.SessionID+"/inbound", "127.0.0.1:51343",
		InboundRequest{UDP: []int{port}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var resp InboundResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.UDP) != 1 {
		t.Fatalf("got %d udp results, want 1", len(resp.UDP))
	}
	if resp.UDP[0].Verdict != probe.UDPOpen {
		t.Errorf("verdict = %q (%s), want open", resp.UDP[0].Verdict, resp.UDP[0].Detail)
	}
}

// Nothing listening on the UDP port: no_response, never open.
func TestInboundUDPNoResponse(t *testing.T) {
	cfg := loopbackConfig()
	cfg.Limits.ProbeTimeout = config.Duration{Duration: 600 * time.Millisecond}
	s := newTestServerWith(t, cfg)
	h := s.Handler()
	sess := openSession(t, h, "127.0.0.1:51343")

	rec := postJSON(t, h, "/v1/session/"+sess.SessionID+"/inbound", "127.0.0.1:51343",
		InboundRequest{UDP: []int{2000}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	var resp InboundResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.UDP) != 1 || resp.UDP[0].Verdict != probe.UDPNoResponse {
		t.Errorf("udp = %+v, want a single no_response verdict", resp.UDP)
	}
}

// The credentials handed out with the session are what the probe is signed
// with, so a client holding them can validate the probe and answer it. A
// client MUST refuse to answer anything else.
func udpClient(t *testing.T, password string) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !stun.Looks(buf[:n]) {
				continue
			}
			msg, err := stun.Decode(buf[:n])
			if err != nil || !msg.CheckMessageIntegrity([]byte(password)) {
				continue
			}
			resp := stun.NewResponse(msg)
			resp.AddXORAddress(stun.AttrXORMappedAddress, from.AddrPort())
			resp.AddMessageIntegrity([]byte(password))
			conn.WriteToUDP(resp.Encode(), from)
		}
	}()

	return int(netip.MustParseAddrPort(conn.LocalAddr().String()).Port())
}

// A client whose address cannot receive inbound traffic at all should be told
// why, not left to read verdicts and reconfigure a router that cannot help.
func TestInboundNotesUnroutableAddress(t *testing.T) {
	cfg := loopbackConfig()
	s := newTestServerWith(t, cfg)
	h := s.Handler()

	sess := openSession(t, h, "127.0.0.1:51343")
	rec := postJSON(t, h, "/v1/session/"+sess.SessionID+"/inbound", "127.0.0.1:51343",
		InboundRequest{TCP: []int{9}})

	var resp InboundResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Notes) == 0 {
		t.Error("an unroutable observed address should produce an explanatory note")
	}
}

func TestSessionEndpointsAreRateLimited(t *testing.T) {
	cfg := loopbackConfig()
	cfg.Limits.SessionsPerHour = 1
	s := newTestServerWith(t, cfg)
	h := s.Handler()

	var last *httptest.ResponseRecorder
	for i := 0; i < 20; i++ {
		last = postJSON(t, h, "/v1/session", "127.0.0.1:51343", SessionRequest{Version: 1})
		if last.Code == http.StatusTooManyRequests {
			break
		}
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("session creation was never rate limited (last %d)", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("a 429 must carry Retry-After")
	}
}

// Exhausting the probing budget must not break the free informational
// endpoint: a client should still be able to learn its own address.
func TestWhoamiStillWorksWhenSessionsAreExhausted(t *testing.T) {
	cfg := loopbackConfig()
	cfg.Limits.SessionsPerHour = 1
	s := newTestServerWith(t, cfg)
	h := s.Handler()

	for i := 0; i < 20; i++ {
		postJSON(t, h, "/v1/session", "127.0.0.1:51343", SessionRequest{Version: 1})
	}
	if rec := do(t, h, "GET", "/v1/whoami", "127.0.0.1:51343"); rec.Code != http.StatusOK {
		t.Errorf("whoami status = %d, want 200", rec.Code)
	}
}

func truncate(s string) string {
	if len(s) > 24 {
		return s[:24] + "..."
	}
	return s
}
