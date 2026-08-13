package control

import (
	"html/template"
	"net/http"
	"strings"
)

// The landing page is an abuse-mitigation control, not decoration.
//
// This service opens TCP connections to residential addresses. Someone will
// see one in a firewall log, look up the reverse DNS, and open it in a
// browser. What they find there decides whether the next step is understanding
// or an abuse report to the hosting provider. So the page answers, in order,
// the questions an annoyed sysadmin actually has: what connected to me, why,
// whether I asked for it, and who to shout at.
var landingTmpl = template.Must(template.New("landing").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Name}} &mdash; DROP connectivity checker</title>
<style>
  :root { color-scheme: light dark; }
  body { max-width: 42rem; margin: 3rem auto; padding: 0 1.25rem;
         font: 16px/1.6 system-ui, sans-serif; }
  h1 { font-size: 1.5rem; }
  h2 { font-size: 1.1rem; margin-top: 2rem; }
  code { font-family: ui-monospace, monospace; font-size: 0.9em; }
  .box { border-left: 3px solid currentColor; padding: 0.1rem 0 0.1rem 1rem;
         opacity: 0.85; }
</style>
</head>
<body>
<h1>DROP connectivity checker</h1>
<p>This host runs <strong>DROP</strong> (Diagnostic Reachability &amp; Obstacle
Probe), a diagnostic service for peer-to-peer file sharing clients. A client
contacts it to find out its own public IP address and whether it can accept
incoming connections.</p>

<h2>Did this host connect to me?</h2>
<p class="box">Then software on your network asked it to, moments earlier, over
an authenticated HTTPS connection from your own address. DROP only ever
connects back to the address that contacted it &mdash; there is no way to ask
it to probe anyone else, and it will not connect to an address that has not
just requested a test.</p>
<p>The connection carries a single line beginning <code>DROP/1 CHALLENGE</code>
and closes immediately. It transfers nothing, reads nothing, and attempts no
login. If nobody on your network runs a Direct Connect client, the most likely
explanation is that your address was recently reassigned from someone who
does.</p>

<h2>Is this a port scanner?</h2>
<p>No. It tests only ports that the requesting client nominated for itself, and
reports a port as reachable only when the client answers a one-time secret sent
over that connection. Requests are rate limited per address and per network.</p>

<h2>Contact</h2>
<p>Questions, complaints, or a request to be excluded:
<a href="mailto:{{.AbuseContact}}">{{.AbuseContact}}</a>{{if .Operator}},
operated by {{.Operator}}{{end}}.</p>

<h2>For client authors</h2>
<p>Machine-readable capabilities: <a href="/v1/server"><code>/v1/server</code></a>.
Your public address: <a href="/v1/whoami"><code>/v1/whoami</code></a>.</p>
</body>
</html>
`))

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	// ServeMux's "GET /" matches everything unmatched, so anything that is not
	// exactly the root is a genuine 404.
	if r.URL.Path != "/" {
		s.writeError(w, http.StatusNotFound, ErrNotFound, "no such endpoint")
		return
	}

	var sb strings.Builder
	if err := landingTmpl.Execute(&sb, s.cfg.Server); err != nil {
		s.log.Error("rendering landing page", "error", err)
		s.writeError(w, http.StatusInternalServerError, ErrUnavailable, "")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sb.String()))
}
