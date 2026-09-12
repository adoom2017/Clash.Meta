# Locally Maintained Quinn Patch

Base: crates.io `quinn-proto` 0.11.17, repository https://github.com/quinn-rs/quinn.

- Crate archive SHA-256: `04759210543be93709136e28212294a659ef5001836ff4eab4d663e4529bba83`.
- VCS: `0343120eb7ccdd067a7e975613b96190c8562bf7` (quinn-proto directory).
- Original Apache-2.0 and MIT licenses retained in `third-party/quinn-proto`.
- Selected locally by `[patch.crates-io]`, including the separate fuzz workspace.

Upstream derives the advertised QUIC DATAGRAM frame limit from the receive queue
capacity. HY2 peers use a 1,200-byte frame limit while requiring a much larger
queue for bursts of UDP fragments. This generic patch adds an optional
`TransportConfig::datagram_max_frame_size` setting and uses the smaller of that
setting and the existing queue size in transport parameters. Omission preserves
upstream behavior; disabling datagrams still disables their advertisement.

Only `src/config/transport.rs` and `src/transport_parameters.rs` change. The patch
contains no proxy protocol semantics or copied third-party proxy implementation.
Hysteria-specific configuration stays in `crates/protocol/src/hysteria2.rs`.

`crates/protocol/tests/quinn_datagrams.rs` independently verifies the advertised
limit with a generic Quinn peer and confirms eight queued datagrams survive
without reducing the aggregate receive buffer to one frame. The official
Hysteria v2.6.4 matrix verifies multi-fragment UDP replies over IPv4/IPv6,
Salamander and forwarded hopping ports.

The v2.6.4 oracle's QUIC implementation can discard its maximum-size outgoing
fragments when the client advertises a large DATAGRAM limit: `SendDatagram`
limits data by its MTU estimate, while packet packing requires additional QUIC
frame/header space. Using the 1,200-byte limit advertised by the official client
avoids that path. References used for analysis, not production dependencies:

- https://github.com/apernet/hysteria/blob/app/v2.6.4/core/internal/protocol/proxy.go
- https://github.com/apernet/quic-go/blob/eb32f8aec5e2/connection.go
- https://github.com/apernet/quic-go/blob/eb32f8aec5e2/packet_packer.go
