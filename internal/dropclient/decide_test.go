package dropclient

import (
	"strings"
	"testing"

	"quickdc.org/drop/internal/natdisc"
)

func res(verdict string) *PortResult { return &PortResult{Verdict: verdict} }

// Every row of the specification's decision table, since this is the part that
// stops each client inventing its own heuristic.
func TestDecide(t *testing.T) {
	cases := []struct {
		name           string
		classification string
		tcp, udp       *PortResult
		wantMode       Mode
		wantReason     string
	}{
		{
			"tcp and udp both open",
			"global", res("open"), res("open"),
			ModeActive, "Active mode works",
		},
		{
			"tcp open, udp silent",
			"global", res("open"), res("no_response"),
			ModeActive, "search results may not arrive",
		},
		{
			// ADC cannot express "passive for transfers, reachable for
			// searches", and advertising anyway makes remote clients attempt
			// CTM to a port that never answers.
			"udp open but tcp filtered",
			"global", res("filtered"), res("open"),
			ModePassive, "no way to advertise that combination",
		},
		{
			"refused",
			"global", res("refused"), res("no_response"),
			ModePassive, "fixable locally",
		},
		{
			"occupied",
			"global", res("occupied"), res("no_response"),
			ModePassive, "not this client",
		},
		{
			"filtered behind cgnat",
			"cgnat", res("filtered"), res("no_response"),
			ModePassive, "carrier-grade NAT",
		},
		{
			"filtered on a global address",
			"global", res("filtered"), res("no_response"),
			ModePassive, "silently dropped",
		},
		{
			"teredo",
			"teredo", res("filtered"), res("no_response"),
			ModePassive, "tunnelled",
		},
		{
			// A private address reaching a public server means a proxy is in
			// the path; no verdict is meaningful.
			"private address observed",
			"private", res("filtered"), res("no_response"),
			ModeUnknown, "proxy or middlebox",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Decide(IPv4, c.classification, c.tcp, c.udp, 1511)
			if d.Mode != c.wantMode {
				t.Errorf("mode = %q, want %q", d.Mode, c.wantMode)
			}
			if !strings.Contains(d.Reason, c.wantReason) {
				t.Errorf("reason %q does not mention %q", d.Reason, c.wantReason)
			}
			if d.Reason == "" {
				t.Error("a decision must always carry a reason")
			}
			if d.Mode == ModePassive && len(d.Remedies) == 0 && c.classification == "global" {
				t.Error("a passive verdict on a routable address should suggest something")
			}
		})
	}
}

// Only an active decision may advertise a port. Advertising while passive is
// what makes remote clients waste time on connections that cannot succeed.
func TestOnlyActiveAdvertisesAPort(t *testing.T) {
	active := Decide(IPv4, "global", res("open"), res("open"), 1511)
	if active.AdvertisePort != 1511 {
		t.Errorf("active: advertise port = %d, want 1511", active.AdvertisePort)
	}

	for _, c := range []struct{ class, tcp, udp string }{
		{"global", "filtered", "open"},
		{"global", "refused", "no_response"},
		{"cgnat", "filtered", "no_response"},
		{"private", "open", "open"},
	} {
		d := Decide(IPv4, c.class, res(c.tcp), res(c.udp), 1511)
		if d.Mode != ModeActive && d.AdvertisePort != 0 {
			t.Errorf("%s/%s/%s: mode %q advertises port %d",
				c.class, c.tcp, c.udp, d.Mode, d.AdvertisePort)
		}
	}
}

// CGNAT advice must point at IPv6, not at the router: no router setting can
// fix a shared address.
func TestCGNATAdviceDoesNotSendUserToTheRouter(t *testing.T) {
	d := Decide(IPv4, "cgnat", res("filtered"), res("no_response"), 1511)
	joined := strings.ToLower(strings.Join(d.Remedies, " "))
	if !strings.Contains(joined, "ipv6") {
		t.Errorf("CGNAT remedies should point at IPv6, got %v", d.Remedies)
	}
	if strings.Contains(joined, "forward the port") {
		t.Errorf("CGNAT remedies must not suggest port forwarding: %v", d.Remedies)
	}
}

// The plain filtered case is the one where port forwarding is the answer, and
// where re-checking afterwards matters, because a router can report success
// while a second NAT upstream still blocks inbound.
func TestFilteredAdviceSuggestsForwardingAndRecheck(t *testing.T) {
	d := Decide(IPv4, "global", res("filtered"), res("no_response"), 1511)
	joined := strings.ToLower(strings.Join(d.Remedies, " "))
	for _, want := range []string{"forward", "re-run"} {
		if !strings.Contains(joined, want) {
			t.Errorf("remedies should mention %q: %v", want, d.Remedies)
		}
	}
}

func TestApplyNAT(t *testing.T) {
	t.Run("blocked udp is reported", func(t *testing.T) {
		d := Decide(IPv4, "global", res("filtered"), res("no_response"), 1511)
		d.ApplyNAT(natdisc.Result{Mapping: natdisc.Blocked})
		if !strings.Contains(d.Note, "Outbound UDP is blocked") {
			t.Errorf("note = %q", d.Note)
		}
	})

	// A server that could not classify must produce silence, not a guess.
	t.Run("unknown says nothing", func(t *testing.T) {
		d := Decide(IPv4, "global", res("filtered"), res("no_response"), 1511)
		d.ApplyNAT(natdisc.Result{Mapping: natdisc.Unknown, Filtering: natdisc.Unknown})
		if d.Note != "" {
			t.Errorf("note = %q, want silence when classification failed", d.Note)
		}
	})

	t.Run("hole punching likely", func(t *testing.T) {
		d := Decide(IPv4, "global", res("filtered"), res("no_response"), 1511)
		d.ApplyNAT(natdisc.Result{
			Mapping:   natdisc.EndpointIndependent,
			Filtering: natdisc.EndpointIndependent,
		})
		if !strings.Contains(d.Note, "hole punching") {
			t.Errorf("note = %q", d.Note)
		}
	})

	t.Run("hole punching hopeless", func(t *testing.T) {
		d := Decide(IPv4, "global", res("filtered"), res("no_response"), 1511)
		d.ApplyNAT(natdisc.Result{
			Mapping:   natdisc.AddressAndPortDependent,
			Filtering: natdisc.AddressAndPortDependent,
		})
		if !strings.Contains(d.Note, "will not work reliably") {
			t.Errorf("note = %q", d.Note)
		}
	})

	// Saying "reachability cannot be measured" and then volunteering NAT
	// advice reads as a contradiction and invites the user to act on it.
	t.Run("silent when the verdict is unknown", func(t *testing.T) {
		d := Decide(IPv4, "private", res("open"), res("open"), 1511)
		if d.Mode != ModeUnknown {
			t.Fatalf("mode = %q, want unknown", d.Mode)
		}
		before := len(d.Remedies)
		d.ApplyNAT(natdisc.Result{
			Mapping:   natdisc.EndpointIndependent,
			Filtering: natdisc.EndpointIndependent,
		})
		if d.Note != "" {
			t.Errorf("note = %q, want silence on an unknown verdict", d.Note)
		}
		if len(d.Remedies) != before {
			t.Errorf("remedies grew from %d to %d on an unknown verdict",
				before, len(d.Remedies))
		}
	})

	// Behaviour discovery must never flip the active/passive verdict: every
	// request in it is client-initiated and says nothing about strangers.
	t.Run("never changes the mode", func(t *testing.T) {
		for _, nat := range []natdisc.Result{
			{Mapping: natdisc.EndpointIndependent, Filtering: natdisc.EndpointIndependent},
			{Mapping: natdisc.AddressAndPortDependent},
			{Mapping: natdisc.Blocked},
			{Mapping: natdisc.NoNAT},
		} {
			d := Decide(IPv4, "global", res("filtered"), res("no_response"), 1511)
			before := d.Mode
			d.ApplyNAT(nat)
			if d.Mode != before {
				t.Errorf("mode changed from %q to %q after applying %v",
					before, d.Mode, nat.Mapping)
			}
		}
	})
}

func TestCombine(t *testing.T) {
	cases := []struct {
		name      string
		decisions []Decision
		want      string
	}{
		{
			"passive everywhere",
			[]Decision{{Family: IPv4, Mode: ModePassive}, {Family: IPv6, Mode: ModePassive}},
			"Passive on every address family",
		},
		{
			// Nothing was measured, so reporting "passive" would assert more
			// than the evidence supports.
			"nothing measurable",
			[]Decision{{Family: IPv4, Mode: ModeUnknown}, {Family: IPv6, Mode: ModeUnknown}},
			"could not be determined",
		},
		{
			"one family unknown, the other active",
			[]Decision{{Family: IPv4, Mode: ModeUnknown}, {Family: IPv6, Mode: ModeActive}},
			"good position",
		},
		{
			"no families tested",
			nil,
			"No address family could be tested",
		},
		{
			// The cross-family rule: this is a materially better position than
			// passive on both, and the user should be told so.
			"active on v6 only",
			[]Decision{{Family: IPv4, Mode: ModePassive}, {Family: IPv6, Mode: ModeActive}},
			"good position",
		},
		{
			"active on v4 only",
			[]Decision{{Family: IPv4, Mode: ModeActive}, {Family: IPv6, Mode: ModePassive}},
			"Active on IPv4",
		},
		{
			"active on both",
			[]Decision{{Family: IPv4, Mode: ModeActive}, {Family: IPv6, Mode: ModeActive}},
			"both address families",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Combine(c.decisions)
			if !strings.Contains(got, c.want) {
				t.Errorf("Combine = %q, want it to mention %q", got, c.want)
			}
		})
	}
}

// A family that errored produces no decision at all, and the summary must not
// describe it. Claiming "passive on IPv6" when IPv6 was never reached asserts
// more than the run established.
func TestCombineDoesNotDescribeUntestedFamilies(t *testing.T) {
	only4 := Combine([]Decision{{Family: IPv4, Mode: ModeActive}})
	if strings.Contains(only4, "passive on IPv6") {
		t.Errorf("summary claims something about an untested family: %q", only4)
	}
	if !strings.Contains(only4, "not tested") {
		t.Errorf("summary should say IPv6 was not tested: %q", only4)
	}

	only6 := Combine([]Decision{{Family: IPv6, Mode: ModeActive}})
	if strings.Contains(only6, "passive on IPv4") {
		t.Errorf("summary claims something about an untested family: %q", only6)
	}

	// With both present, the cross-family wording still applies.
	both := Combine([]Decision{{Family: IPv4, Mode: ModePassive}, {Family: IPv6, Mode: ModeActive}})
	if !strings.Contains(both, "good position") {
		t.Errorf("cross-family advice lost: %q", both)
	}
}
