package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"quickdc.org/drop/internal/ipclass"
	"quickdc.org/drop/internal/probe"
	"quickdc.org/drop/internal/session"
)

// SessionRequest is the body of POST /v1/session.
//
// Note what is absent: there is no address here, and there never may be. The
// probe target is the source of this very connection.
type SessionRequest struct {
	Version int      `json:"version"`
	Client  string   `json:"client"`
	Tests   []string `json:"tests"`
}

// SessionResponse is returned by POST /v1/session.
type SessionResponse struct {
	SessionID string        `json:"session_id"`
	ExpiresIn int           `json:"expires_in"`
	Observed  ObservedDoc   `json:"observed"`
	STUN      *STUNDoc      `json:"stun,omitempty"`
	Creds     *CredentialsD `json:"credentials,omitempty"`
	Limits    LimitsDoc     `json:"limits"`
}

// ObservedDoc is what the server sees of the client.
type ObservedDoc struct {
	IP             string `json:"ip"`
	Family         string `json:"family"`
	Port           int    `json:"port"`
	Classification string `json:"classification"`
}

// CredentialsD carries RFC 8489 short-term credentials for the UDP tests.
type CredentialsD struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// InboundRequest is the body of POST /v1/session/{id}/inbound.
//
// As with SessionRequest, there is deliberately no address field.
type InboundRequest struct {
	TCP []int `json:"tcp"`
	UDP []int `json:"udp"`

	// ControlPort is the local source port of this very control connection,
	// as the client's own socket sees it.
	//
	// It is optional and purely diagnostic. Comparing it with the port the
	// server observed is what reveals TCP source-port rewriting, and it is the
	// only local port the server can say anything useful about: a listening
	// port compared against the nominated port tells the server nothing the
	// client did not already know.
	ControlPort int `json:"control_port,omitempty"`
}

// InboundResponse reports the probe outcomes.
type InboundResponse struct {
	SessionID string            `json:"session_id"`
	Observed  ObservedDoc       `json:"observed"`
	TCP       []probe.TCPResult `json:"tcp,omitempty"`
	UDP       []probe.UDPResult `json:"udp,omitempty"`
	Notes     []string          `json:"notes,omitempty"`
	ElapsedMS int               `json:"elapsed_ms"`
}

func (s *Server) handleSessionCreate(w http.ResponseWriter, r *http.Request) {
	peer, err := PeerAddr(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, ErrMalformed, err.Error())
		return
	}
	// Creating a session is what leads to the server emitting traffic, so it
	// is charged against the strict budget rather than the cheap one.
	if !s.allow(w, s.sessionLimit, peer.Addr()) {
		return
	}

	var req SessionRequest
	if !s.decodeBody(w, r, &req) {
		return
	}

	sess, err := s.sessions.Issue(peer.Addr())
	if err != nil {
		s.log.Error("issuing session", "error", err)
		s.writeError(w, http.StatusServiceUnavailable, ErrUnavailable, "")
		return
	}

	resp := SessionResponse{
		SessionID: sess.ID,
		ExpiresIn: int(time.Until(sess.Expires).Seconds()),
		Observed:  observedOf(peer),
		Limits:    s.serverDoc.Limits,
		Creds: &CredentialsD{
			Username: sess.STUNUsername,
			Password: sess.STUNPassword,
		},
	}
	// Advertise only the endpoints of the family this session is for; the
	// other family's endpoints are unreachable from here anyway.
	resp.STUN = s.stunFor(peer.Addr())

	w.Header().Set("Cache-Control", "no-store")
	s.metrics.Count("drop_sessions_issued_total", "Sessions issued.",
		"family", familyOf(peer.Addr()))
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSessionInbound(w http.ResponseWriter, r *http.Request) {
	peer, err := PeerAddr(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, ErrMalformed, err.Error())
		return
	}

	id := r.PathValue("id")
	sess, err := s.sessions.Parse(id, peer.Addr())
	if err != nil {
		s.writeSessionError(w, err)
		return
	}

	var req InboundRequest
	if !s.decodeBody(w, r, &req) {
		return
	}

	tcpPorts, err := s.validatePorts(req.TCP)
	if err != nil {
		s.writePortError(w, err)
		return
	}
	udpPorts, err := s.validatePorts(req.UDP)
	if err != nil {
		s.writePortError(w, err)
		return
	}
	if len(tcpPorts) == 0 && len(udpPorts) == 0 {
		s.writeError(w, http.StatusBadRequest, ErrMalformed,
			"name at least one tcp or udp port to test")
		return
	}

	// Single use. Consumed before any probe runs, so a client cannot retry its
	// way around the rate limit by reusing one session.
	if err := s.sessions.Consume(sess); err != nil {
		s.writeSessionError(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Limits.InboundDeadline.Duration)
	defer cancel()

	start := s.now()
	resp := InboundResponse{
		SessionID: sess.ID,
		Observed:  observedOf(peer),
	}

	if len(tcpPorts) > 0 {
		prober := &probe.TCPProber{
			LocalAddr: s.probeSourceFor(peer.Addr()),
			Timeout:   s.cfg.Limits.ProbeTimeout.Duration,
		}
		resp.TCP = prober.ProbeTCPAll(ctx, sess.Addr, tcpPorts, func(port int) string {
			return s.sessions.Nonce(sess, "tcp", port)
		})
		for _, res := range resp.TCP {
			s.metrics.Count("drop_tcp_probes_total", "Inbound TCP probes by verdict.",
				"verdict", string(res.Verdict))
		}
	}

	if len(udpPorts) > 0 {
		prober := &probe.UDPProber{
			LocalAddr: s.probeSourceFor(peer.Addr()),
			Timeout:   s.cfg.Limits.ProbeTimeout.Duration,
		}
		resp.UDP = prober.ProbeUDPAll(ctx, sess.Addr, udpPorts,
			sess.STUNUsername, sess.STUNPassword)
		for _, res := range resp.UDP {
			s.metrics.Count("drop_udp_probes_total", "Inbound UDP probes by verdict.",
				"verdict", string(res.Verdict))
		}
	}

	// A client whose observed address cannot receive inbound traffic at all
	// deserves to be told why, rather than reading four "filtered" verdicts
	// and going to reconfigure a router that cannot help.
	if class := ipclass.Of(peer.Addr()); !class.Routable() {
		resp.Notes = append(resp.Notes, class.Advice())
	}
	if req.ControlPort != 0 && peer.Port() != 0 && int(peer.Port()) != req.ControlPort {
		resp.Notes = append(resp.Notes, fmt.Sprintf(
			"This connection left your machine on port %d but reached us as port %d, "+
				"so a NAT is rewriting TCP source ports. Port forwarding is therefore "+
				"required for inbound connections.", req.ControlPort, peer.Port()))
	}

	resp.ElapsedMS = int(s.now().Sub(start).Milliseconds())
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusOK, resp)
}

// validatePorts checks the requested ports against the configured caps and
// returns them deduplicated.
func (s *Server) validatePorts(ports []int) ([]int, error) {
	if len(ports) == 0 {
		return nil, nil
	}
	if len(ports) > s.cfg.Limits.MaxPortsPerTest {
		return nil, fmt.Errorf("%w: at most %d ports per test",
			errTooManyPorts, s.cfg.Limits.MaxPortsPerTest)
	}

	seen := map[int]bool{}
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p < s.cfg.Limits.MinPort || p > 65535 {
			// The floor matters behind carrier-grade NAT, where a probe aimed
			// at "the client" can land on a different subscriber: it keeps the
			// common administrative services out of reach when that happens.
			return nil, fmt.Errorf("%w: ports must be between %d and 65535",
				errPortRange, s.cfg.Limits.MinPort)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

var (
	errPortRange    = errors.New("port out of range")
	errTooManyPorts = errors.New("too many ports")
)

func (s *Server) writePortError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errTooManyPorts):
		s.writeError(w, http.StatusUnprocessableEntity, ErrTooManyPorts, err.Error())
	default:
		s.writeError(w, http.StatusUnprocessableEntity, ErrPortRange, err.Error())
	}
}

func (s *Server) writeSessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, session.ErrWrongSource):
		// Deliberately 403 rather than 404: the session is real, but the
		// address changed, and the results would be meaningless or aimed at a
		// stranger.
		s.writeError(w, http.StatusForbidden, ErrWrongSource,
			"this session was issued to a different address")
	case errors.Is(err, session.ErrAlreadyRan):
		s.writeError(w, http.StatusConflict, ErrAlreadyRan,
			"open a new session for another test")
	case errors.Is(err, session.ErrExpired), errors.Is(err, session.ErrMalformed),
		errors.Is(err, session.ErrBadMAC):
		s.writeError(w, http.StatusNotFound, ErrUnknownSession,
			"unknown or expired session")
	case errors.Is(err, session.ErrTooMany):
		s.writeError(w, http.StatusServiceUnavailable, ErrUnavailable,
			"the server is at capacity; try again shortly")
	default:
		s.log.Error("session error", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrUnavailable, "")
	}
}

// decodeBody reads a JSON body, rejecting unknown fields.
//
// Rejecting unknown fields is a deliberate choice here despite the
// specification telling clients to ignore unknown members in *responses*: a
// request naming something the server does not understand is a client that
// believes it asked for something it did not get.
func (s *Server) decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeError(w, http.StatusRequestEntityTooLarge, ErrTooLarge, "")
			return false
		}
		s.writeError(w, http.StatusBadRequest, ErrMalformed, err.Error())
		return false
	}
	return true
}

func observedOf(peer netip.AddrPort) ObservedDoc {
	return ObservedDoc{
		IP:             peer.Addr().String(),
		Family:         familyOf(peer.Addr()),
		Port:           int(peer.Port()),
		Classification: string(ipclass.Of(peer.Addr())),
	}
}

func familyOf(addr netip.Addr) string {
	if addr.Is6() {
		return "ipv6"
	}
	return "ipv4"
}

// probeSourceFor returns the address probes to addr should be sent from, which
// is this family's primary bind address. Probing from an unbound socket would
// let the kernel choose, and a client told to expect one address would see
// another.
func (s *Server) probeSourceFor(addr netip.Addr) netip.Addr {
	f, ok := s.cfg.STUN[familyOf(addr)]
	if !ok {
		return netip.Addr{}
	}
	bind, err := netip.ParseAddr(f.PrimaryBind)
	if err != nil {
		return netip.Addr{}
	}
	return bind
}

// stunFor returns the STUN endpoints for the family of addr.
func (s *Server) stunFor(addr netip.Addr) *STUNDoc {
	family := familyOf(addr)
	f, ok := s.cfg.STUN[family]
	if !ok {
		return nil
	}
	doc := &STUNDoc{Primary: &STUNEndpoint{Port: f.PrimaryPort}}
	setFamilyAddr(doc.Primary, family, f.PrimaryAdvertise)
	if f.HasAlternate() {
		doc.Alternate = &STUNEndpoint{Port: f.AlternatePort}
		setFamilyAddr(doc.Alternate, family, f.AlternateAdvertise)
	}
	return doc
}
