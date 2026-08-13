package control

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"quickdc.org/drop/internal/config"
)

func testConfig() config.Config {
	c := config.Default()
	c.Server.Name = "drop.example.org"
	c.Server.Operator = "example.org"
	c.Server.AbuseContact = "abuse@example.org"
	c.Control.Hostnames = []string{"drop.example.org"}
	c.STUN = map[string]config.Family{
		"ipv4": {
			PrimaryBind:      "198.51.100.10",
			PrimaryAdvertise: "198.51.100.10",
			PrimaryPort:      3478,
		},
		"ipv6": {
			PrimaryBind:        "2001:db8:1::10",
			PrimaryAdvertise:   "2001:db8:1::10",
			PrimaryPort:        3478,
			AlternateBind:      "2001:db8:1::11",
			AlternateAdvertise: "2001:db8:1::11",
			AlternatePort:      3479,
		},
	}
	if err := c.Validate(); err != nil {
		panic(err)
	}
	return c
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(testConfig(), log)
}

func do(t *testing.T, h http.Handler, method, target, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestWhoamiReportsObservedAddress(t *testing.T) {
	h := newTestServer(t).Handler()
	rec := do(t, h, "GET", "/v1/whoami", "203.0.113.7:51343")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var doc WhoamiDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.IP != "203.0.113.7" {
		t.Errorf("ip = %q", doc.IP)
	}
	if doc.Family != "ipv4" {
		t.Errorf("family = %q", doc.Family)
	}
	if doc.Port != 51343 {
		t.Errorf("port = %d, want the observed source port", doc.Port)
	}
	if doc.Classification != "global" {
		t.Errorf("classification = %q", doc.Classification)
	}
	if doc.Advice == "" {
		t.Error("advice should never be empty")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("whoami must be CORS-open for browser clients, got %q", got)
	}
}

func TestWhoamiClassifiesCGNAT(t *testing.T) {
	h := newTestServer(t).Handler()
	rec := do(t, h, "GET", "/v1/whoami", "100.64.1.1:40000")

	var doc WhoamiDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Classification != "cgnat" {
		t.Errorf("classification = %q, want cgnat", doc.Classification)
	}
	if !strings.Contains(doc.Advice, "carrier-grade NAT") {
		t.Errorf("advice should explain CGNAT, got %q", doc.Advice)
	}
}

func TestWhoamiIPv6(t *testing.T) {
	h := newTestServer(t).Handler()
	rec := do(t, h, "GET", "/v1/whoami", "[2001:db8::1]:51343")

	var doc WhoamiDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Family != "ipv6" || doc.IP != "2001:db8::1" {
		t.Errorf("got %q / %q", doc.Family, doc.IP)
	}
}

// A dual-stack listener presents IPv4 clients as ::ffff:a.b.c.d. Reporting
// that verbatim would confuse every client and break the CGNAT advice.
func TestWhoamiUnmapsIPv4MappedAddresses(t *testing.T) {
	h := newTestServer(t).Handler()
	rec := do(t, h, "GET", "/v1/whoami", "[::ffff:100.64.1.1]:40000")

	var doc WhoamiDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.IP != "100.64.1.1" {
		t.Errorf("ip = %q, want the unmapped form", doc.IP)
	}
	if doc.Family != "ipv4" {
		t.Errorf("family = %q, want ipv4", doc.Family)
	}
	if doc.Classification != "cgnat" {
		t.Errorf("classification = %q, want cgnat", doc.Classification)
	}
}

// The forwarded-address headers are the obvious way to turn this service into
// an aimable port scanner, so they must have no effect whatsoever.
func TestWhoamiIgnoresForwardedHeaders(t *testing.T) {
	h := newTestServer(t).Handler()

	for _, hdr := range []struct{ name, value string }{
		{"X-Forwarded-For", "198.51.100.99"},
		{"X-Real-IP", "198.51.100.99"},
		{"Forwarded", "for=198.51.100.99"},
		{"X-Client-IP", "198.51.100.99"},
	} {
		req := httptest.NewRequest("GET", "/v1/whoami", nil)
		req.RemoteAddr = "203.0.113.7:51343"
		req.Header.Set(hdr.name, hdr.value)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		var doc WhoamiDoc
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.IP != "203.0.113.7" {
			t.Errorf("%s changed the observed address to %q", hdr.name, doc.IP)
		}
	}
}

func TestServerDocPerFamilyCapabilities(t *testing.T) {
	h := newTestServer(t).Handler()
	rec := do(t, h, "GET", "/v1/server", "203.0.113.7:51343")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var doc ServerDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Protocol != Protocol {
		t.Errorf("protocol = %q", doc.Protocol)
	}
	if doc.AbuseContact == "" {
		t.Error("abuse contact must be advertised")
	}

	// The whole point of the per-family split: IPv6 has a second address here
	// and IPv4 does not, so only IPv6 may advertise "nat".
	if has(doc.Tests["ipv4"], "nat") {
		t.Error("ipv4 has no alternate address and must not advertise nat")
	}
	if !has(doc.Tests["ipv6"], "nat") {
		t.Error("ipv6 has an alternate address and should advertise nat")
	}

	if doc.STUN == nil || doc.STUN.Primary == nil {
		t.Fatal("primary STUN endpoint should be advertised")
	}
	if doc.STUN.Primary.IPv4 != "198.51.100.10" {
		t.Errorf("primary ipv4 = %q", doc.STUN.Primary.IPv4)
	}
	if doc.STUN.Alternate == nil || doc.STUN.Alternate.IPv6 != "2001:db8:1::11" {
		t.Errorf("alternate ipv6 endpoint missing or wrong: %+v", doc.STUN.Alternate)
	}
	// IPv4 has no alternate, so the alternate endpoint must carry no v4 address.
	if doc.STUN.Alternate != nil && doc.STUN.Alternate.IPv4 != "" {
		t.Errorf("alternate ipv4 = %q, want empty", doc.STUN.Alternate.IPv4)
	}
}

// Bound addresses must never leak into the capability document: clients that
// tried to reach an anchor address would fail, and the operator would see
// nothing wrong locally.
func TestServerDocAdvertisesNeverBindAddresses(t *testing.T) {
	cfg := testConfig()
	cfg.STUN["ipv4"] = config.Family{
		PrimaryBind:        "201.79.4.56",
		PrimaryAdvertise:   "201.79.4.56",
		PrimaryPort:        3478,
		AlternateBind:      "10.19.0.6", // DigitalOcean anchor
		AlternateAdvertise: "203.0.113.9",
		AlternatePort:      3479,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec := do(t, s.Handler(), "GET", "/v1/server", "203.0.113.7:51343")

	if strings.Contains(rec.Body.String(), "10.19.0.6") {
		t.Errorf("the bind (anchor) address leaked into the capability document:\n%s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "203.0.113.9") {
		t.Errorf("the advertised address is missing:\n%s", rec.Body)
	}
}

func TestEgressPortClasses(t *testing.T) {
	h := newTestServer(t).Handler()
	rec := do(t, h, "GET", "/v1/server", "203.0.113.7:51343")

	var doc ServerDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Egress.BannerPorts) == 0 {
		t.Error("banner ports should be advertised")
	}
	// 80 and 443 cannot speak first, so they must not be listed as banner
	// ports -- a client would wait for a banner that never arrives.
	for _, p := range doc.Egress.BannerPorts {
		if p == 80 || p == 443 {
			t.Errorf("port %d cannot emit a banner and must not be a banner port", p)
		}
	}
	if !hasInt(doc.Egress.HTTPPorts, 80) {
		t.Errorf("http_ports = %v, want 80", doc.Egress.HTTPPorts)
	}
	if !hasInt(doc.Egress.HTTPSPorts, 443) {
		t.Errorf("https_ports = %v, want 443", doc.Egress.HTTPSPorts)
	}
}

func TestLandingPageAnswersTheAbuseQuestion(t *testing.T) {
	h := newTestServer(t).Handler()
	rec := do(t, h, "GET", "/", "203.0.113.7:51343")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	// Whoever lands here found this host in a firewall log. The page has to
	// answer them, or the next step is an abuse report to the provider.
	for _, want := range []string{"abuse@example.org", "DROP/1 CHALLENGE", "port scanner"} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page does not mention %q", want)
		}
	}
}

func TestUnknownPathIs404(t *testing.T) {
	h := newTestServer(t).Handler()
	rec := do(t, h, "GET", "/v1/nope", "203.0.113.7:51343")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestRateLimitReturns429WithRetryAfter(t *testing.T) {
	s := newTestServer(t)
	h := s.Handler()

	var last *httptest.ResponseRecorder
	for i := 0; i < 200; i++ {
		last = do(t, h, "GET", "/v1/whoami", "203.0.113.7:51343")
		if last.Code == http.StatusTooManyRequests {
			break
		}
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("never rate limited after 200 requests (last status %d)", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("a 429 must carry Retry-After")
	}
	var doc ErrorDoc
	if err := json.Unmarshal(last.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Error != ErrRateLimited {
		t.Errorf("error code = %q", doc.Error)
	}
}

// Port 80 must not expose anything carrying a session or a credential.
func TestPlaintextHandlerSurfaceIsMinimal(t *testing.T) {
	s := newTestServer(t)
	h := s.PlaintextHandler()

	// The capability document is needed there: it is how the egress test on
	// port 80 confirms it reached a DROP server and not a captive portal.
	if rec := do(t, h, "GET", "/v1/server", "203.0.113.7:1"); rec.Code != http.StatusOK {
		t.Errorf("/v1/server over plaintext: status = %d, want 200", rec.Code)
	}
	if rec := do(t, h, "GET", "/", "203.0.113.7:1"); rec.Code != http.StatusOK {
		t.Errorf("landing page over plaintext: status = %d, want 200", rec.Code)
	}

	// Everything else redirects to the canonical TLS host.
	rec := do(t, h, "GET", "/v1/session/abc/inbound", "203.0.113.7:1")
	if rec.Code != http.StatusPermanentRedirect {
		t.Errorf("session path over plaintext: status = %d, want a redirect", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://drop.example.org/") {
		t.Errorf("Location = %q, want the configured host over https", loc)
	}
}

// The Host header is attacker-controlled. Reflecting it into a redirect would
// make this an open redirector.
func TestRedirectIgnoresHostHeader(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "http://evil.example.com/v1/session", nil)
	req.Host = "evil.example.com"
	req.RemoteAddr = "203.0.113.7:1"
	rec := httptest.NewRecorder()
	s.PlaintextHandler().ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "evil.example.com") {
		t.Errorf("Location %q reflects the attacker-supplied Host", loc)
	}
}

// The structural guarantee behind the whole service: the server probes the
// source address of the control connection and nothing else. This walks every
// exported request type looking for a field that could carry a target
// address, so that the rule survives contributors who have not read the spec.
func TestNoRequestTypeCanCarryATargetAddress(t *testing.T) {
	// Register every type that is decoded from a client request body. Adding
	// a new request type without adding it here is caught in review; adding an
	// address field to one of these is caught right now.
	requestTypes := []reflect.Type{}
	for _, v := range requestBodyTypes() {
		requestTypes = append(requestTypes, reflect.TypeOf(v))
	}

	banned := []string{"ip", "addr", "address", "host", "target", "peer", "dest", "destination"}

	for _, rt := range requestTypes {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			name := strings.ToLower(f.Name)
			for _, b := range banned {
				if strings.Contains(name, b) {
					t.Errorf("%s.%s looks like it carries an address; the probe "+
						"target must come only from the connection's source address",
						rt.Name(), f.Name)
				}
			}
		}
	}
}

func has(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func hasInt(list []int, want int) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
