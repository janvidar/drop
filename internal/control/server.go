package control

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"quickdc.org/drop/internal/config"
	"quickdc.org/drop/internal/ipclass"
	"quickdc.org/drop/internal/metrics"
	"quickdc.org/drop/internal/ratelimit"
	"quickdc.org/drop/internal/session"
)

// maxBodyBytes caps request bodies. Every legitimate DROP request is a few
// hundred bytes; the cap exists so that an attacker cannot make the server
// buffer megabytes per connection.
const maxBodyBytes = 8 << 10

// Server is the control plane.
type Server struct {
	cfg config.Config
	log *slog.Logger
	now func() time.Time

	// cheap limits the unauthenticated informational endpoints; sessionLimit
	// limits the endpoints that cause the server to emit traffic. They are
	// separate because /v1/whoami costs nothing and should stay usable even
	// when a client has exhausted its probing budget.
	cheap        *ratelimit.Limiter
	sessionLimit *ratelimit.Limiter

	sessions  *session.Manager
	metrics   *metrics.Registry
	serverDoc ServerDoc
}

// New builds a Server from configuration.
//
// The secret is the per-server key behind every session token, challenge nonce
// and STUN credential. It is passed in rather than generated here so that it
// can live in the state directory and survive a restart; regenerating it would
// invalidate every session in flight.
func New(cfg config.Config, log *slog.Logger, secret []byte) (*Server, error) {
	sessions, err := session.NewManager(secret,
		cfg.Limits.SessionTTL.Duration, cfg.Limits.MaxSessions)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:      cfg,
		log:      log,
		now:      time.Now,
		metrics:  metrics.New(),
		sessions: sessions,
		cheap: ratelimit.New(ratelimit.Config{
			Host:       ratelimit.Rule{Every: time.Second, Burst: 30},
			Prefix:     ratelimit.Rule{Every: time.Second / 4, Burst: 120},
			MaxEntries: 8192,
		}),
		sessionLimit: ratelimit.New(ratelimit.DefaultConfig(cfg.Limits.SessionsPerHour)),
	}
	s.serverDoc = s.buildServerDoc()

	s.metrics.RegisterRuntime()
	s.metrics.Gauge("drop_ratelimit_buckets", "Rate-limit buckets currently held.",
		func() float64 { return float64(s.cheap.Len() + s.sessionLimit.Len()) })
	s.metrics.Gauge("drop_sessions_consumed", "Sessions that have run their inbound test.",
		func() float64 { return float64(s.sessions.Active()) })

	return s, nil
}

// Metrics returns the registry, so main can expose it on the loopback
// listener. It is not routed on the public handler: it is unauthenticated.
func (s *Server) Metrics() *metrics.Registry { return s.metrics }

// buildServerDoc renders the capability document once at startup. It never
// changes at runtime, and rendering it per request would be pure waste on a
// single-core host.
func (s *Server) buildServerDoc() ServerDoc {
	doc := ServerDoc{
		Protocol:     Protocol,
		Server:       s.cfg.Server.Name,
		Operator:     s.cfg.Server.Operator,
		AbuseContact: s.cfg.Server.AbuseContact,
		Tests:        map[string][]string{},
		Egress: EgressDoc{
			BannerPorts: s.cfg.Egress.BannerPorts,
			HTTPPorts:   portsOf(s.cfg.Control.HTTPAddr),
			HTTPSPorts:  portsOf(s.cfg.Control.HTTPSAddr),
		},
		Limits: LimitsDoc{
			MaxPortsPerTest:   s.cfg.Limits.MaxPortsPerTest,
			MinPort:           s.cfg.Limits.MinPort,
			SessionsPerHour:   s.cfg.Limits.SessionsPerHour,
			ProbeTimeoutMS:    int(s.cfg.Limits.ProbeTimeout.Milliseconds()),
			InboundDeadlineMS: int(s.cfg.Limits.InboundDeadline.Milliseconds()),
		},
	}

	stun := &STUNDoc{}
	for family, f := range s.cfg.STUN {
		// Only tests that are actually implemented are advertised, so a client
		// never sees a capability the server cannot deliver. "udp" joins this
		// list when the inbound UDP probe lands.
		tests := []string{"tcp", "udp", "egress"}
		if f.HasAlternate() {
			tests = append(tests, "nat")
		}
		doc.Tests[family] = tests

		if stun.Primary == nil {
			stun.Primary = &STUNEndpoint{Port: f.PrimaryPort}
		}
		setFamilyAddr(stun.Primary, family, f.PrimaryAdvertise)
		if f.HasAlternate() {
			if stun.Alternate == nil {
				stun.Alternate = &STUNEndpoint{Port: f.AlternatePort}
			}
			setFamilyAddr(stun.Alternate, family, f.AlternateAdvertise)
		}

		switch family {
		case "ipv4":
			doc.Egress.IPv4 = f.PrimaryAdvertise
		case "ipv6":
			doc.Egress.IPv6 = f.PrimaryAdvertise
		}
	}
	if stun.Primary != nil {
		doc.STUN = stun
	}
	return doc
}

func setFamilyAddr(e *STUNEndpoint, family, addr string) {
	if family == "ipv4" {
		e.IPv4 = addr
	} else {
		e.IPv6 = addr
	}
}

// portsOf extracts the port from a listen address like ":443" as a one-element
// list, so the capability document can name it.
func portsOf(addr string) []int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 {
		return nil
	}
	return []int{p}
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/server", s.handleServer)
	mux.HandleFunc("GET /v1/whoami", s.handleWhoami)
	mux.HandleFunc("POST /v1/session", s.handleSessionCreate)
	mux.HandleFunc("POST /v1/session/{id}/inbound", s.handleSessionInbound)
	mux.HandleFunc("GET /", s.handleLanding)
	return s.withCommonHeaders(mux)
}

// connKey carries the local address a connection arrived on, which tells the
// handlers which of our own addresses the client reached.
type connKey struct{}

// ConnContext is installed on http.Server so handlers can see the local
// address. Without it a dual-homed server cannot tell which of its addresses a
// client used.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c.LocalAddr())
}

// LocalAddr returns the address the request arrived on, if known.
func LocalAddr(r *http.Request) (netip.AddrPort, bool) {
	v, ok := r.Context().Value(connKey{}).(net.Addr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(v.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return ap, true
}

// PeerAddr returns the source address of the request.
//
// This is the only place the probe target ever comes from. It reads
// http.Request.RemoteAddr, which net/http fills from the accepted connection,
// and deliberately consults no forwarded-address header: X-Forwarded-For and
// Forwarded are attacker-controlled unless a trusted proxy set them, and DROP
// is specified to run without a proxy precisely so that this value can be
// trusted. Honouring such a header here would turn the service into a port
// scanner aimable at any address.
func PeerAddr(r *http.Request) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		// Fall back for transports without a port, e.g. a Unix socket in tests.
		addr, err2 := netip.ParseAddr(r.RemoteAddr)
		if err2 != nil {
			return netip.AddrPort{}, fmt.Errorf("unparseable remote address %q: %w", r.RemoteAddr, err)
		}
		return netip.AddrPortFrom(addr.Unmap(), 0), nil
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()), nil
}

func (s *Server) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// The control plane is a machine API; there is nothing to frame or to
		// embed, and no reason for a browser to run anything from it.
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		s.metrics.Count("drop_http_requests_total", "Control-plane requests.",
			"endpoint", endpointLabel(r.URL.Path),
			"status", strconv.Itoa(rec.status))
	})
}

// statusRecorder captures the response status for metrics.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if !w.written {
		w.status = code
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

// endpointLabel maps a request path onto a small fixed set.
//
// The path is attacker-controlled, so using it directly as a metric label
// would let anyone grow the registry without bound by requesting random URLs
// -- a memory exhaustion vector dressed up as observability.
func endpointLabel(path string) string {
	switch {
	case path == "/v1/server":
		return "server"
	case path == "/v1/whoami":
		return "whoami"
	case path == "/v1/session":
		return "session"
	case strings.HasPrefix(path, "/v1/session/"):
		return "session_inbound"
	case path == "/":
		return "landing"
	default:
		return "other"
	}
}

func (s *Server) handleServer(w http.ResponseWriter, r *http.Request) {
	peer, err := PeerAddr(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, ErrMalformed, err.Error())
		return
	}
	if !s.allow(w, s.cheap, peer.Addr()) {
		return
	}
	// The capability document is static and safe to cache briefly; clients
	// fetch it on every startup.
	w.Header().Set("Cache-Control", "public, max-age=300")
	s.writeJSON(w, http.StatusOK, s.serverDoc)
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	peer, err := PeerAddr(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, ErrMalformed, err.Error())
		return
	}
	if !s.allow(w, s.cheap, peer.Addr()) {
		return
	}

	class := ipclass.Of(peer.Addr())
	family := "ipv4"
	if peer.Addr().Is6() {
		family = "ipv6"
	}

	// Browser clients can at least learn their address; this endpoint has no
	// side effects and reveals only what the browser's own connection already
	// told us. The session endpoints get no CORS, since a browser cannot run
	// the inbound tests anyway.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store")

	s.writeJSON(w, http.StatusOK, WhoamiDoc{
		IP:             peer.Addr().String(),
		Family:         family,
		Port:           int(peer.Port()),
		Classification: string(class),
		Advice:         class.Advice(),
		ObservedAt:     s.now().UTC().Truncate(time.Second),
	})
}

// allow applies a rate limiter, writing a 429 and reporting false when the
// request must be rejected.
func (s *Server) allow(w http.ResponseWriter, l *ratelimit.Limiter, addr netip.Addr) bool {
	ok, wait := l.Allow(addr)
	if ok {
		return true
	}
	secs := int(wait.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	s.writeError(w, http.StatusTooManyRequests, ErrRateLimited,
		fmt.Sprintf("try again in %ds", secs))
	return false
}

func (s *Server) writeJSON(w http.ResponseWriter, code int, body any) {
	buf, err := json.Marshal(body)
	if err != nil {
		// Marshalling our own types cannot fail in practice; if it does, the
		// response is already compromised, so say as little as possible.
		s.log.Error("marshalling response", "error", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	buf = append(buf, '\n')
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(buf)))
	w.WriteHeader(code)
	_, _ = w.Write(buf)
}

func (s *Server) writeError(w http.ResponseWriter, code int, errCode, detail string) {
	s.writeJSON(w, code, ErrorDoc{Error: errCode, Detail: detail})
}

// ListenAndServe is a convenience used by tests and by main.
func (s *Server) HTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:        addr,
		Handler:     h,
		ConnContext: ConnContext,
		ErrorLog:    slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),

		// An internet-facing server without these will eventually be held open
		// by slow or abandoned connections until it runs out of descriptors.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// The write timeout must outlast the inbound deadline, or the response
		// carrying the probe results is cut off before it can be sent.
		WriteTimeout:   s.cfg.Limits.InboundDeadline.Duration + 15*time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
}
