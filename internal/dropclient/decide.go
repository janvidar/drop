package dropclient

import (
	"fmt"

	"quickdc.org/drop/internal/natdisc"
)

// Mode is the recommendation a client should act on.
type Mode string

const (
	// ModeActive: advertise the TCP4/TCP6 feature token and the U4/U6 port.
	ModeActive Mode = "active"
	// ModePassive: advertise neither.
	ModePassive Mode = "passive"
	// ModeUnknown: the test could not establish anything useful, usually
	// because a proxy is in the path. Do not change existing settings.
	ModeUnknown Mode = "unknown"
)

// Decision is the outcome of one family's run.
type Decision struct {
	Family Family `json:"family"`
	Mode   Mode   `json:"mode"`

	// AdvertisePort is the port to put in U4/U6, if any.
	AdvertisePort int `json:"advertise_port,omitempty"`

	// Reason is the one-line explanation to show the user.
	Reason string `json:"reason"`
	// Remedies are concrete next steps, in the order worth trying.
	Remedies []string `json:"remedies,omitempty"`

	TCP  string `json:"tcp_verdict,omitempty"`
	UDP  string `json:"udp_verdict,omitempty"`
	Note string `json:"note,omitempty"`
}

// Decide applies the specification's decision table.
//
// It lives here, in one place, so that every client reaches the same
// conclusion from the same evidence. The alternative -- each client inventing
// its own heuristic -- is how users end up getting contradictory advice from
// different software about the same network.
//
// Two things about ADC shape the outcomes. Active mode is signalled by the
// TCP4/TCP6 feature tokens in the INF SU field, while U4/U6 carry the UDP port
// for search results; deployed hubs disagree about which of the two they look
// at, so a client must set them consistently. And there is no way in ADC to
// say "passive for transfers but reachable for search results": advertising
// U4/U6 is read as a wholesale active-mode claim.
func Decide(family Family, classification string, tcp, udp *PortResult, tcpPort int) Decision {
	d := Decision{Family: family, Mode: ModePassive}
	if tcp != nil {
		d.TCP = tcp.Verdict
	}
	if udp != nil {
		d.UDP = udp.Verdict
	}

	// A private or loopback address observed by a public server means a proxy
	// or middlebox is rewriting traffic. No verdict from here is meaningful,
	// and reporting one would send the user somewhere useless.
	switch classification {
	case "private", "unique-local", "loopback":
		d.Mode = ModeUnknown
		d.Reason = "A private address reached the server, so a proxy or middlebox " +
			"is rewriting your traffic. Reachability cannot be measured from here."
		return d
	}

	tcpOpen := tcp != nil && tcp.Verdict == "open"
	udpOpen := udp != nil && udp.Verdict == "open"

	switch {
	case tcpOpen && udpOpen:
		d.Mode = ModeActive
		d.AdvertisePort = tcpPort
		d.Reason = "Inbound TCP and UDP both reach you. Active mode works."

	case tcpOpen && !udpOpen:
		// Transfers will work; search results over UDP will not arrive.
		d.Mode = ModeActive
		d.AdvertisePort = tcpPort
		d.Reason = "Inbound TCP reaches you, but unsolicited UDP does not. " +
			"Transfers will work; search results may not arrive."
		d.Remedies = []string{
			"Forward the same port for UDP as well as TCP.",
		}

	case !tcpOpen && udpOpen:
		// ADC cannot express this state. Advertising would make remote clients
		// attempt CTM to a port that does not answer, which is worse for
		// everyone than being honestly passive.
		d.Mode = ModePassive
		d.Reason = "UDP reaches you but inbound TCP does not. ADC has no way to " +
			"advertise that combination, so passive mode is the honest choice."
		d.Remedies = []string{
			"Forward the TCP port as well; the UDP forward alone is not enough.",
		}

	case tcp != nil && tcp.Verdict == "refused":
		d.Reason = "The connection was refused: packets reach your network and " +
			"nothing is listening. Nothing is being dropped, so this is usually " +
			"fixable locally."
		d.Remedies = []string{
			"Check the client is actually listening on that port.",
			"Check any port forward points at this machine, not another one.",
		}

	case tcp != nil && tcp.Verdict == "occupied":
		d.Reason = "Something answered on that port, but it was not this client. " +
			"A forward is probably pointing at the wrong host."
		d.Remedies = []string{
			"Check the port forward's destination address.",
			"Try a different port.",
		}

	case classification == "cgnat":
		// The one case where no amount of router configuration helps.
		d.Reason = "Your ISP uses carrier-grade NAT: this address is shared with " +
			"other subscribers, so inbound connections cannot be forwarded to you."
		d.Remedies = []string{
			"Enable IPv6 if your ISP offers it; that is the real fix.",
			"Ask your ISP for a public IPv4 address, which some provide on request.",
		}

	case classification == "teredo", classification == "6to4":
		d.Reason = fmt.Sprintf("Your IPv6 connectivity is tunnelled (%s) and "+
			"inbound connections are not getting through.", classification)
		d.Remedies = []string{"Use native IPv6 if your ISP offers it."}

	default:
		d.Reason = "Inbound connections are being silently dropped: a firewall " +
			"or NAT is in the way."
		d.Remedies = []string{
			"Forward the port on your router, or enable UPnP-IGD / NAT-PMP / PCP.",
			"Check the firewall on this machine allows inbound connections.",
			"Re-run this check afterwards: a router can report success while a " +
				"second NAT upstream still blocks inbound.",
		}
	}

	return d
}

// ApplyNAT folds behaviour-discovery results into a decision.
//
// Behaviour discovery never changes the active/passive verdict: every request
// in it is client-initiated, so a good result says nothing about whether
// strangers can reach the client. It only adds prognosis about hole punching.
func (d *Decision) ApplyNAT(nat natdisc.Result) {
	// When the observed address already told us a proxy is in the path, every
	// measurement from here is suspect. Volunteering NAT advice on top of
	// "reachability cannot be measured" is worse than saying nothing: it reads
	// as a contradiction and invites the user to act on it.
	if d.Mode == ModeUnknown {
		return
	}

	switch {
	case nat.Mapping == natdisc.Blocked:
		d.Note = "Outbound UDP is blocked entirely, so UDP search results cannot " +
			"work on this network regardless of port forwarding."
	case nat.Mapping == natdisc.Unknown:
		// Silence is better than a guess: a server that cannot classify must
		// not be reported as a restrictive NAT.
		return
	case d.Mode == ModeActive:
		return // hole punching is moot when inbound already works
	case nat.HolePunchLikely():
		d.Note = "Your NAT is well behaved, so hole punching (ADC's NATT " +
			"extension) has a good chance of working with other clients."
		d.Remedies = append(d.Remedies,
			"Enable NAT traversal in your client if it supports it.")
	default:
		d.Note = fmt.Sprintf("Your NAT uses %s mapping, so hole punching will not "+
			"work reliably. A forwarded port is the only dependable option.", nat.Mapping)
	}
}

// Combine merges the per-family decisions into advice for the user.
//
// The cross-family rule matters: a client active on IPv6 and passive on IPv4
// is in a materially better position than one passive on both, and should be
// told so rather than simply reported as "passive".
func Combine(decisions []Decision) string {
	var activeFamilies []Family
	measured := 0
	for _, d := range decisions {
		if d.Mode == ModeActive {
			activeFamilies = append(activeFamilies, d.Family)
		}
		if d.Mode != ModeUnknown {
			measured++
		}
	}

	// Nothing was actually measured, so "passive" would be an assertion the
	// evidence does not support.
	if measured == 0 {
		if len(decisions) == 0 {
			return "No address family could be tested."
		}
		return "Reachability could not be determined on any address family, so " +
			"no change to your active-mode setting is recommended."
	}

	// Describe only the families actually decided. A family that errored is
	// absent from this slice, and calling it "passive" would assert something
	// the run never established.
	both := len(decisions) > 1

	switch len(activeFamilies) {
	case 0:
		return "Passive on every address family that could be tested. Other " +
			"clients will not be able to connect to you directly, and transfers " +
			"with other passive users will not work at all."
	case 1:
		if activeFamilies[0] == IPv6 {
			if !both {
				return "Active on IPv6. IPv4 was not tested."
			}
			return "Active on IPv6, passive on IPv4. This is a good position: you " +
				"can connect directly with any other IPv6 client, which is most of " +
				"what carrier-grade NAT would otherwise cost you."
		}
		if !both {
			return "Active on IPv4. IPv6 was not tested."
		}
		return "Active on IPv4, passive on IPv6."
	default:
		return "Active on both address families."
	}
}
