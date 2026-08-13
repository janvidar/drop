// Package ipclass classifies an observed address into the categories the DROP
// specification defines for the "classification" member of /v1/whoami.
//
// The classification is not cosmetic. It is what lets a client tell a user
// "your ISP uses carrier-grade NAT and no router setting will fix this" rather
// than sending them to fiddle with port forwards that cannot work.
package ipclass

import "net/netip"

// Class is the set of values the specification enumerates.
type Class string

const (
	Global      Class = "global"
	CGNAT       Class = "cgnat"
	Private     Class = "private"
	UniqueLocal Class = "unique-local"
	Loopback    Class = "loopback"
	Teredo      Class = "teredo"
	SixToFour   Class = "6to4"

	// LinkLocal and Unspecified are not in the specification's enumeration
	// because a public server should never observe them. They exist so that
	// the classifier is total and never silently reports "global" for an
	// address that is obviously not.
	LinkLocal   Class = "link-local"
	Unspecified Class = "unspecified"
)

// Routable reports whether a client at an address of this class could ever be
// reachable from the public Internet. A false result means the reachability
// probes are not worth running: something in the path is proxying, or the
// address is shared and not the client's to forward.
func (c Class) Routable() bool {
	return c == Global || c == Teredo || c == SixToFour
}

// Advice is a short, user-facing explanation of what the class implies. It is
// deliberately here rather than in each client, so that users get the same
// explanation regardless of which DC client they run.
func (c Class) Advice() string {
	switch c {
	case Global:
		return "Ordinary public address."
	case CGNAT:
		return "Your ISP uses carrier-grade NAT: this address is shared with " +
			"other subscribers, so inbound connections cannot be forwarded to " +
			"you. No router setting will change that. IPv6 is the remedy."
	case Private, UniqueLocal, Loopback:
		return "A private address reached a public server, so a proxy or " +
			"middlebox is rewriting your traffic. Reachability results are " +
			"not meaningful from here."
	case Teredo:
		return "Teredo tunnelled IPv6. Usable but slow and widely deprecated; " +
			"native IPv6 is much better if your ISP offers it."
	case SixToFour:
		return "6to4 tunnelled IPv6. Widely deprecated and often broken; " +
			"native IPv6 is much better if your ISP offers it."
	case LinkLocal:
		return "A link-local address reached a public server, which should be " +
			"impossible. Something is badly misconfigured."
	default:
		return "Unrecognised address."
	}
}

// Prefixes evaluated in order. First match wins, so more specific prefixes
// must come before the ranges that contain them.
var table = []struct {
	prefix netip.Prefix
	class  Class
}{
	// IPv4. 100.64.0.0/10 (RFC 6598) must precede nothing in particular but
	// is listed early because it is the one that changes a user's options.
	{netip.MustParsePrefix("100.64.0.0/10"), CGNAT},
	{netip.MustParsePrefix("10.0.0.0/8"), Private},
	{netip.MustParsePrefix("172.16.0.0/12"), Private},
	{netip.MustParsePrefix("192.168.0.0/16"), Private},
	{netip.MustParsePrefix("127.0.0.0/8"), Loopback},
	{netip.MustParsePrefix("169.254.0.0/16"), LinkLocal},
	{netip.MustParsePrefix("0.0.0.0/8"), Unspecified},

	// IPv6. Teredo and 6to4 are both inside 2000::/3 global unicast, so they
	// must be tested before any global-unicast catch-all.
	{netip.MustParsePrefix("2001::/32"), Teredo},
	{netip.MustParsePrefix("2002::/16"), SixToFour},
	{netip.MustParsePrefix("fc00::/7"), UniqueLocal},
	{netip.MustParsePrefix("fe80::/10"), LinkLocal},
	{netip.MustParsePrefix("::1/128"), Loopback},
	{netip.MustParsePrefix("::/128"), Unspecified},
}

// Of classifies addr.
//
// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are unmapped first, so that a
// dual-stack listener classifies a v4 client the same way a v4-only listener
// would. Getting this wrong would report every v4 client behind a dual-stack
// socket as "global" even when it is carrier-grade NATted.
func Of(addr netip.Addr) Class {
	if !addr.IsValid() {
		return Unspecified
	}
	addr = addr.Unmap().WithZone("")

	for _, e := range table {
		if e.prefix.Contains(addr) {
			return e.class
		}
	}
	return Global
}

// OfString is a convenience wrapper for callers holding a textual address.
// An unparseable address classifies as Unspecified rather than erroring,
// because every caller would otherwise have to handle a condition that only
// arises from a programming mistake.
func OfString(s string) Class {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return Unspecified
	}
	return Of(addr)
}
