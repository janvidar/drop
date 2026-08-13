package control

import (
	"fmt"
	"net/netip"

	"quickdc.org/drop/internal/config"
	"quickdc.org/drop/internal/stunsrv"
)

// STUNServers builds one STUN server per configured address family.
//
// They are constructed here rather than in main so that the credential lookup
// stays wired to the same session manager that issued the credentials, and so
// the capability document and the servers cannot disagree about which families
// support behaviour discovery.
func (s *Server) STUNServers(software string) ([]*stunsrv.Server, error) {
	var out []*stunsrv.Server

	for _, family := range []string{"ipv4", "ipv6"} {
		f, ok := s.cfg.STUN[family]
		if !ok {
			continue
		}
		srv, err := s.stunServerFor(family, f, software)
		if err != nil {
			return nil, err
		}
		out = append(out, srv)
	}
	return out, nil
}

func (s *Server) stunServerFor(family string, f config.Family, software string) (*stunsrv.Server, error) {
	primaryBind, err := netip.ParseAddr(f.PrimaryBind)
	if err != nil {
		return nil, fmt.Errorf("stun.%s: primary_bind: %w", family, err)
	}
	primaryAdv, err := netip.ParseAddr(f.PrimaryAdvertise)
	if err != nil {
		return nil, fmt.Errorf("stun.%s: primary_advertise: %w", family, err)
	}

	eps := []*stunsrv.Endpoint{{
		Role:      stunsrv.Role{},
		Bind:      netip.AddrPortFrom(primaryBind, uint16(f.PrimaryPort)),
		Advertise: netip.AddrPortFrom(primaryAdv, uint16(f.PrimaryPort)),
	}}

	if f.HasAlternate() {
		altBind, err := netip.ParseAddr(f.AlternateBind)
		if err != nil {
			return nil, fmt.Errorf("stun.%s: alternate_bind: %w", family, err)
		}
		altAdv, err := netip.ParseAddr(f.AlternateAdvertise)
		if err != nil {
			return nil, fmt.Errorf("stun.%s: alternate_advertise: %w", family, err)
		}
		pp, ap := uint16(f.PrimaryPort), uint16(f.AlternatePort)

		// RFC 5780 needs all four combinations of the two addresses and the
		// two ports; three endpoints is not enough to tell address-dependent
		// mapping from address-and-port-dependent.
		eps = append(eps,
			&stunsrv.Endpoint{
				Role:      stunsrv.Role{AltAddr: true},
				Bind:      netip.AddrPortFrom(altBind, pp),
				Advertise: netip.AddrPortFrom(altAdv, pp),
			},
			&stunsrv.Endpoint{
				Role:      stunsrv.Role{AltPort: true},
				Bind:      netip.AddrPortFrom(primaryBind, ap),
				Advertise: netip.AddrPortFrom(primaryAdv, ap),
			},
			&stunsrv.Endpoint{
				Role:      stunsrv.Role{AltAddr: true, AltPort: true},
				Bind:      netip.AddrPortFrom(altBind, ap),
				Advertise: netip.AddrPortFrom(altAdv, ap),
			},
		)
	}

	return &stunsrv.Server{
		Family:      family,
		Endpoints:   eps,
		Credentials: s.sessions.Credential,
		Software:    software,
		Log:         s.log,
		OnRequest: func(role stunsrv.Role, outcome string) {
			s.metrics.Count("drop_stun_requests_total", "STUN requests served.",
				"family", family, "endpoint", role.String(), "outcome", outcome)
		},
	}, nil
}
