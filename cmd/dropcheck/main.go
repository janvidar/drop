// Command dropcheck is the reference DROP client.
//
// It runs the whole flow the way a DC client should, and prints what a user
// needs to know. It doubles as the conformance tester for a DROP server: if
// dropcheck reports sensible results from a real network, the server works.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"quickdc.org/drop/internal/dropclient"
	"quickdc.org/drop/internal/natdisc"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "dropcheck: %v\n", err)
		os.Exit(1)
	}
}

type familyRun struct {
	Family   dropclient.Family         `json:"family"`
	BaseURL  string                    `json:"base_url"`
	Whoami   *dropclient.WhoamiDoc     `json:"whoami,omitempty"`
	Inbound  *dropclient.InboundDoc    `json:"inbound,omitempty"`
	NAT      *natdisc.Result           `json:"nat,omitempty"`
	Notes    []string                  `json:"notes,omitempty"`
	Egress   []dropclient.EgressResult `json:"egress,omitempty"`
	Decision *dropclient.Decision      `json:"decision,omitempty"`
	Error    string                    `json:"error,omitempty"`
}

type report struct {
	Server  string      `json:"server"`
	Version string      `json:"version"`
	Runs    []familyRun `json:"runs"`
	Advice  string      `json:"advice"`
}

func run() error {
	var (
		server      = flag.String("server", "", "base URL, e.g. https://drop.example.org (required)")
		v4Host      = flag.String("v4", "", "IPv4-only base URL (default: the -server host prefixed with ipv4.)")
		v6Host      = flag.String("v6", "", "IPv6-only base URL (default: the -server host prefixed with ipv6.)")
		families    = flag.String("family", "both", "which families to test: ipv4, ipv6 or both")
		tcpPort     = flag.Int("tcp-port", 0, "TCP port to test (default: an ephemeral one)")
		udpPort     = flag.Int("udp-port", 0, "UDP port to test (default: an ephemeral one)")
		bindAddr    = flag.String("bind", "", "local address to bind, which is the address that gets tested")
		skipEgress  = flag.Bool("skip-egress", false, "skip the outbound-reachability test")
		skipNAT     = flag.Bool("skip-nat", false, "skip NAT behaviour discovery")
		asJSON      = flag.Bool("json", false, "emit JSON instead of prose")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("dropcheck %s\n", version)
		return nil
	}
	if *server == "" {
		flag.Usage()
		return errors.New("-server is required")
	}

	v4URL, v6URL := *v4Host, *v6Host
	if v4URL == "" {
		v4URL = familyURL(*server, "ipv4")
	}
	if v6URL == "" {
		v6URL = familyURL(*server, "ipv6")
	}

	var wanted []struct {
		family dropclient.Family
		url    string
	}
	switch *families {
	case "ipv4":
		wanted = append(wanted, struct {
			family dropclient.Family
			url    string
		}{dropclient.IPv4, v4URL})
	case "ipv6":
		wanted = append(wanted, struct {
			family dropclient.Family
			url    string
		}{dropclient.IPv6, v6URL})
	case "both":
		wanted = append(wanted,
			struct {
				family dropclient.Family
				url    string
			}{dropclient.IPv4, v4URL},
			struct {
				family dropclient.Family
				url    string
			}{dropclient.IPv6, v6URL})
	default:
		return fmt.Errorf("unknown -family %q", *families)
	}

	var bind netip.Addr
	if *bindAddr != "" {
		var err error
		bind, err = netip.ParseAddr(*bindAddr)
		if err != nil {
			return fmt.Errorf("-bind: %w", err)
		}
	}

	rep := report{Server: *server, Version: version}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	for _, w := range wanted {
		r := familyRun{Family: w.family, BaseURL: w.url}
		if err := runFamily(ctx, &r, w.url, w.family, bind, *tcpPort, *udpPort, *skipEgress, *skipNAT); err != nil {
			r.Error = err.Error()
		}
		rep.Runs = append(rep.Runs, r)
	}

	var decisions []dropclient.Decision
	for _, r := range rep.Runs {
		if r.Decision != nil {
			decisions = append(decisions, *r.Decision)
		}
	}
	rep.Advice = dropclient.Combine(decisions)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	printReport(rep)
	return nil
}

// familyURL turns https://drop.example.org into https://ipv4.drop.example.org.
//
// The family-specific names exist so that the family under test is never
// ambiguous: relying on Happy Eyeballs would make it depend on which
// connection won the race.
func familyURL(base, prefix string) string {
	base = strings.TrimRight(base, "/")
	for _, scheme := range []string{"https://", "http://"} {
		if rest, ok := strings.CutPrefix(base, scheme); ok {
			return scheme + prefix + "." + rest
		}
	}
	return prefix + "." + base
}

func runFamily(ctx context.Context, out *familyRun, baseURL string, family dropclient.Family,
	bind netip.Addr, tcpPort, udpPort int, skipEgress, skipNAT bool) error {

	c := dropclient.New(baseURL, family, bind)
	c.UserAgent = "dropcheck/" + version

	doc, err := c.Server(ctx)
	if err != nil {
		return err
	}

	whoami, err := c.Whoami(ctx)
	if err != nil {
		return err
	}
	out.Whoami = whoami

	// Source-port rewriting, detected locally: the port this client bound and
	// the port the server saw are the two ends of one connection. Doing it
	// here rather than by sending control_port is what makes it correct.
	if local := c.LocalPort(); local != 0 && whoami.Port != 0 && local != whoami.Port {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"This connection left your machine on port %d but reached the "+
				"server as port %d, so a NAT is rewriting source ports.",
			local, whoami.Port))
	}

	// Arm the listeners *before* asking for the probes. A client that asks
	// first races the server's connection against its own bind.
	network := "tcp4"
	udpNetwork := "udp4"
	listenHost := "0.0.0.0"
	if family == dropclient.IPv6 {
		network, udpNetwork, listenHost = "tcp6", "udp6", "::"
	}
	if bind.IsValid() {
		listenHost = bind.String()
	}

	// JoinHostPort, not Sprintf: an IPv6 literal must be bracketed, and "::"
	// formatted naively yields ":::0".
	tcpResp, err := dropclient.ListenTCP(network,
		net.JoinHostPort(listenHost, strconv.Itoa(tcpPort)))
	if err != nil {
		return fmt.Errorf("listening for the TCP challenge: %w", err)
	}
	defer tcpResp.Close()

	sess, err := c.OpenSession(ctx, nil)
	if err != nil {
		return err
	}

	// The UDP responder must hold the credentials before the probe arrives,
	// and must answer only requests that authenticate against them.
	udpResp, err := dropclient.ListenUDP(udpNetwork,
		net.JoinHostPort(listenHost, strconv.Itoa(udpPort)),
		func(username string) (string, bool) {
			if username != sess.Creds.Username {
				return "", false
			}
			return sess.Creds.Password, true
		})
	if err != nil {
		return fmt.Errorf("listening for the UDP probe: %w", err)
	}
	defer udpResp.Close()

	inbound, err := c.Inbound(ctx, sess.SessionID,
		[]int{tcpResp.Port()}, []int{udpResp.Port()})
	if err != nil {
		return err
	}
	out.Inbound = inbound

	var tcpRes, udpRes *dropclient.PortResult
	if len(inbound.TCP) > 0 {
		tcpRes = &inbound.TCP[0]
	}
	if len(inbound.UDP) > 0 {
		udpRes = &inbound.UDP[0]
	}

	decision := dropclient.Decide(family, whoami.Classification, tcpRes, udpRes, tcpResp.Port())

	if !skipNAT && supports(doc, string(family), "nat") {
		nat, err := c.DiscoverNAT(ctx, sess, udpResp.Port())
		if err == nil {
			out.NAT = &nat
			decision.ApplyNAT(nat)
		}
	}
	if !skipEgress {
		out.Egress = c.TestEgress(ctx, doc)
	}

	out.Decision = &decision
	return nil
}

func supports(doc *dropclient.ServerDoc, family, test string) bool {
	for _, t := range doc.Tests[family] {
		if t == test {
			return true
		}
	}
	return false
}

func printReport(rep report) {
	for _, r := range rep.Runs {
		fmt.Printf("== %s ==\n", strings.ToUpper(string(r.Family)))
		if r.Error != "" {
			fmt.Printf("  could not test: %s\n\n", r.Error)
			continue
		}

		if r.Whoami != nil {
			fmt.Printf("  Public address:  %s (%s)\n", r.Whoami.IP, r.Whoami.Classification)
			if r.Whoami.Advice != "" && r.Whoami.Classification != "global" {
				fmt.Printf("                   %s\n", wrap(r.Whoami.Advice, 19))
			}
		}
		if r.Inbound != nil {
			for _, p := range r.Inbound.TCP {
				fmt.Printf("  Inbound TCP:     port %d: %s%s\n", p.Port, p.Verdict, detail(p))
			}
			for _, p := range r.Inbound.UDP {
				fmt.Printf("  Inbound UDP:     port %d: %s%s\n", p.Port, p.Verdict, detail(p))
			}
			for _, n := range r.Notes {
				fmt.Printf("  Note:            %s\n", wrap(n, 19))
			}
			for _, n := range r.Inbound.Notes {
				fmt.Printf("  Note:            %s\n", wrap(n, 19))
			}
		}
		if r.NAT != nil {
			fmt.Printf("  NAT mapping:     %s\n", r.NAT.Mapping)
			fmt.Printf("  NAT filtering:   %s\n", r.NAT.Filtering)
			if r.NAT.Mapping != natdisc.NoNAT && r.NAT.Mapping != natdisc.Blocked {
				fmt.Printf("  Port preserved:  %v\n", r.NAT.PortPreserving)
			}
			for _, n := range r.NAT.Notes {
				fmt.Printf("  Note:            %s\n", wrap(n, 19))
			}
		}
		if len(r.Egress) > 0 {
			var blocked []string
			for _, e := range r.Egress {
				if !e.Reached {
					blocked = append(blocked, fmt.Sprint(e.Port))
				}
			}
			if len(blocked) == 0 {
				fmt.Printf("  Outbound:        all tested ports reachable\n")
			} else {
				fmt.Printf("  Outbound:        blocked on %s\n", strings.Join(blocked, ", "))
			}
		}

		if r.Decision != nil {
			fmt.Printf("\n  VERDICT:         %s\n", strings.ToUpper(string(r.Decision.Mode)))
			fmt.Printf("  %s\n", wrap(r.Decision.Reason, 2))
			if r.Decision.Note != "" {
				fmt.Printf("  %s\n", wrap(r.Decision.Note, 2))
			}
			if len(r.Decision.Remedies) > 0 {
				fmt.Printf("\n  What to try:\n")
				for _, rem := range r.Decision.Remedies {
					fmt.Printf("    - %s\n", wrap(rem, 6))
				}
			}
		}
		fmt.Println()
	}

	fmt.Printf("== SUMMARY ==\n  %s\n", wrap(rep.Advice, 2))
}

func detail(p dropclient.PortResult) string {
	if p.Detail == "" {
		return ""
	}
	return " (" + p.Detail + ")"
}

// wrap reflows text at 78 columns with a hanging indent, so long explanations
// stay readable in a terminal.
func wrap(s string, indent int) string {
	const width = 78
	pad := strings.Repeat(" ", indent)
	var out strings.Builder
	col := indent

	for i, word := range strings.Fields(s) {
		if i > 0 {
			if col+1+len(word) > width {
				out.WriteString("\n" + pad)
				col = indent
			} else {
				out.WriteString(" ")
				col++
			}
		}
		out.WriteString(word)
		col += len(word)
	}
	return out.String()
}
