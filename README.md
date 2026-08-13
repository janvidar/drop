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

    cmd/dropd/          the server
    cmd/dropcheck/      reference client and conformance tester
    internal/config/    configuration; bind vs advertise per STUN endpoint
    internal/control/   HTTPS control plane
    internal/ipclass/   address classification (global / cgnat / private / ...)
    internal/ratelimit/ bounded per-address and per-prefix token buckets
    internal/metrics/   Prometheus text endpoint
    deploy/             systemd unit and example configuration

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

## Status

Implemented: the control plane (`/v1/server`, `/v1/whoami`), the landing page,
rate limiting, metrics, TLS via in-process ACME.

Not yet implemented: the inbound TCP probe, the inbound UDP probe, RFC 5780
behaviour discovery, the egress listeners, and `dropcheck`. The capability
document only ever advertises tests the server can actually run, so a client
talking to a partially deployed server degrades correctly.
