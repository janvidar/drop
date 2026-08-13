package control

import (
	"net/http"
	"net/url"
)

// PlaintextHandler serves the port-80 listener.
//
// The specification requires the control plane to be TLS-only, but port 80
// still has two jobs that TLS cannot do. It is a low port for the egress test
// to aim at -- the case DROP is diagnosing is a network that blocks outbound
// traffic, and such networks frequently permit 80 and nothing else -- and it
// is where a sysadmin who found this host in a firewall log will land.
//
// So the plaintext surface is deliberately minimal: the landing page, and the
// capability document that the egress test needs to confirm it truly reached a
// DROP server rather than a captive portal. Nothing that carries a session, a
// credential, or a probe request is reachable without TLS; those redirect.
func (s *Server) PlaintextHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/server", s.handleServer)
	mux.HandleFunc("GET /", s.handleLandingOrRedirect)
	return s.withCommonHeaders(mux)
}

func (s *Server) handleLandingOrRedirect(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		s.handleLanding(w, r)
		return
	}
	s.redirectToHTTPS(w, r)
}

// redirectToHTTPS sends the client to the canonical TLS endpoint.
//
// The redirect target is built from the configured server name rather than
// from the request's Host header. A Host header is attacker-controlled, and
// reflecting it into a Location would let anyone use this endpoint as an open
// redirector.
func (s *Server) redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := url.URL{
		Scheme:   "https",
		Host:     s.cfg.Server.Name,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
}
