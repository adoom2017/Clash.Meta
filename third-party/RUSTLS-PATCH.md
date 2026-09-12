# Locally Maintained rustls Patch

Base: upstream `rustls` **0.23.44**, crates.io source archive.

- Upstream repository: https://github.com/rustls/rustls
- Crate VCS commit: `64ad386785c718c74262b79e6893813db381adfe`
- Original `.crate` SHA-256: `6725596c3f2c3a0aef021139e145d4eafe314a6623e4680ca83852b2c67ab2ba`
- Original licenses retained: Apache-2.0, ISC and MIT.
- Local copy: `third-party/rustls`; selected through `[patch.crates-io]`.

The patch is implemented in this repository, not sourced from a third-party TLS
fork. It adds only the generic hooks needed to authenticate a legacy session ID:

1. `client/client_conn.rs`: optional `SessionIdCustomizer` and configuration field.
2. `client/builder.rs`: default the customizer to `None`.
3. `client/hs.rs`: serialize the complete zero-session-ID ClientHello, call the
   customizer with the active key exchange, and install its result before the
   transcript is hashed. Reject retries, resumption, ECH and TLS 1.2 for this path.
4. `crypto/mod.rs`: opt-in non-consuming additional peer-secret derivation; default
   key exchanges reject this operation.
5. `msgs/handshake.rs`: internal constructor for a fixed 32-byte session ID.
6. `lib.rs`: export the customizer from the client API.

REALITY-specific key derivation, timestamps, short IDs, AES-GCM and certificate
HMAC verification live in `crates/protocol/src/reality.rs`. Standard connections
leave the hook disabled. Secret derivation uses audited general cryptography
libraries rather than local cipher implementations.

Independent local tests cover ClientHello transcript binding, low-order X25519
keys, authenticated/forged certificate signatures, single-use authentication
state, ordinary TLS certificate rejection and TLS data transfer. The fixed-version
official Xray v25.9.11 tests passed on Windows x64, including the full REALITY
handshake, wrong public key/SNI/short-id rejection and reconnection after a server
restart. Exact coverage and binary checksums are in `docs/vless-protocol.md`.

Comparison with the checksum-verified upstream crate confirms changes in only
the six source files listed above (34 inserted lines, one replaced line). The
registry-generated `.cargo-ok` cache marker is not part of this source copy.

This copy alone is not a complete dependency snapshot. Use
`scripts/prepare-offline.ps1` to archive it together with the workspace's locked
registry sources and their licenses/checksums. The resulting archive has passed
empty-cache offline builds on Windows x64 and Linux x64; see
`docs/offline-build.md` for the exact artifact and verification scope.
