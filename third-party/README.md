# Foundation Dependencies

Production protocol implementations are repository-owned. Cargo dependencies
provide runtimes, serialization, standard cryptography, TLS, QUIC/HTTP3, HTTP,
DNS wire types, TCP/IP and operating-system interfaces. No external proxy kernel
or protocol project is linked, vendored, loaded or launched by the product.

Local foundation patches:

- `rustls/`: see `RUSTLS-PATCH.md` for the minimal REALITY/Vision handshake hooks.
- `quinn-proto/`: see `QUINN-PATCH.md` for the separate DATAGRAM frame/queue limits.

Original upstream licenses are preserved in each directory. `Cargo.lock` pins
registry versions and checksums. `scripts/prepare-offline.ps1` creates the full
registry source snapshot, package/license inventory, per-file hashes and archive
SHA-256. The archive includes these maintained local patches. External Xray and
Hysteria binaries are checksum-pinned test fixtures under ignored `target/oracles`;
they are excluded from production source archives and release packages.

Windows native TUN uses the official Wintun runtime through the general tun-rs
device library. Obtain the signed `wintun.dll` and its license from wintun.net;
the repository does not redistribute an unverified driver binary.
