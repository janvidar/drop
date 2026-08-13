# DROP — Diagnostic Reachability & Obstacle Probe

DROP tells a peer-to-peer client what its public address is and whether inbound
TCP and UDP actually reach it, so the client can decide correctly whether to
advertise ADC active mode — and tell the user *why* not when the answer is no.

The protocol specification is [`docs/drop.txt`](docs/drop.txt). It is the
normative document; this is one implementation of it. The service is
independent of any particular hub software.

## Why

ADC guarantees peer-to-peer transfers only when at least one side is *active*,
able to accept an inbound TCP connection. Two passive clients cannot connect to
each other at all. Clients get this wrong constantly, for mundane reasons: they
do not know their public address, whether a NAT needs a forwarded port, or
whether a firewall is silently dropping inbound SYNs. Nothing in the ecosystem
measures it — hubs infer "active" purely from the client having claimed a port,
and never verify the claim.

## What it is not

DROP does not open ports; that is PCP, NAT-PMP or UPnP-IGD. It is the
closed-loop *verification* of those, which a mapping protocol cannot give you
on its own — a router can grant a mapping while a second, carrier-grade NAT
upstream still blocks inbound.

It is also not a port scanner, and the design makes that structural rather than
a matter of policy: **the server probes the source address of the control
connection and nothing else.** There is no target-address parameter in the
protocol, and a unit test walks every request type to keep it that way.

## Layout

    cmd/dropd/           the server
    cmd/dropcheck/       reference client and conformance tester
    internal/config/     configuration; bind vs advertise per STUN endpoint
    internal/control/    HTTPS control plane
    internal/session/    stateless session tokens, nonces, STUN credentials
    internal/probe/      inbound TCP and UDP probes
    internal/stun/       RFC 8489 + RFC 5780 message encoding
    internal/stunsrv/    STUN server, four endpoints per family
    internal/natdisc/    client-side NAT behaviour classification
    internal/egress/     banner listeners for the outbound test
    internal/dropclient/ reference client library and the decision table
    internal/ipclass/    address classification (global / cgnat / private / ...)
    internal/ratelimit/  bounded per-address and per-prefix token buckets
    internal/metrics/    Prometheus text endpoint
    deploy/              systemd unit and example configuration

If you are implementing DROP in another client, read
[`internal/dropclient/client.go`](internal/dropclient/client.go) for the flow
and [`internal/dropclient/decide.go`](internal/dropclient/decide.go) for what to
do with the results. The decision table lives in one place on purpose: the
alternative is every client inventing its own heuristic and users getting
contradictory advice about the same network.

## Build

    go build ./cmd/dropd
    go test ./...

One dependency (`github.com/BurntSushi/toml`) plus `golang.org/x/crypto` for
in-process ACME. Builds with Go 1.22.

## Run

    dropd -config /etc/dropd/dropd.toml
    dropd -check-config -config ./dropd.toml    # validate and exit

See [`deploy/dropd.toml.example`](deploy/dropd.toml.example). The one
configuration subtlety worth reading before deploying is that STUN endpoints
have a **bind** address and an **advertise** address, and on some cloud
providers they legitimately differ — see the comments in that file.

## Check your own connection

    dropcheck -server https://drop.example.org

Add `-json` for machine-readable output, `-bind <addr>` to choose which of your
addresses gets tested, and `-family ipv4|ipv6|both`.

## Status

All server-side tests are implemented: the control plane, the inbound TCP probe,
the inbound UDP probe over STUN, RFC 5780 behaviour discovery, and the egress
listeners. The capability document only ever advertises tests the server can
actually run, so a client talking to a partially configured server degrades
correctly — a family with only one address simply does not offer `nat`.

The specification is still marked DRAFT pending review by client authors.

### A note on RFC 5780 in the wild

Measured against five public STUN servers in August 2026, three returned no
`OTHER-ADDRESS` at all and the two that did ignored `CHANGE-REQUEST` entirely.
So the mapping half of behaviour discovery is widely available and the filtering
half effectively is not, which is why DROP runs its own STUN server rather than
pointing clients at a public one. A server that cannot classify filtering must
report `unknown`, never `address-and-port-dependent` — the latter is
indistinguishable from the most restrictive NAT there is and would send users
chasing a firewall problem they do not have.
