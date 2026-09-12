# Hysteria 2 Implementation

The repository implements HTTP/3 authentication, TCP request/response framing,
UDP fragmentation/reassembly, Salamander and port hopping. Production links only
general networking/cryptography libraries. Official Hysteria is a test oracle.

Automatic bandwidth mode uses Quinn's CUBIC congestion controller. Explicit
upload bandwidth additionally enables repository-owned packet pacing. The chosen
rate is the smaller of client upload and nonzero server receive limits. Server
`Hysteria-CC-RX: auto` overrides explicit upload bandwidth and uses congestion
control alone. Client download bandwidth is sent in authentication; the server
applies its own negotiated transmit policy. This is not an implementation of the
external Brutal congestion-control project.

Authentication is bounded to 15 seconds per QUIC/auth phase; TCP establishment
is bounded to 15 seconds. HTTP/3 background work is aborted when authentication
is cancelled or the client drops. UDP supports 256 sessions per QUIC connection,
64 queued frames per session, 64 pending packets per reassembler, a five-second
fragment lifetime and an 8 MiB shared fragment payload budget per connection.
Packets are limited to 65,507 bytes locally. Duplicate conflicting fragments,
inconsistent metadata and invalid indices are rejected. Concurrent sends on one
session are serialized because official peers keep one fragmented packet at a
time. UDP itself does not retransmit lost datagrams.

Quinn's receive queue remains 2 MiB while the advertised frame limit is 1,200
bytes, using the generic local patch in `third-party/QUINN-PATCH.md`. Hopping
changes destination ports on the configured interval (minimum five seconds),
normalizes allowed reply ports to the canonical QUIC peer, and preserves existing
streams. The server/network must forward those ports to the same QUIC service.

## Verification

```powershell
./scripts/test-hysteria2.ps1
cargo test -p meta-protocol --locked --offline --lib --test quinn_datagrams
```

The script downloads and checks the official Windows x64 release v2.6.4. Other
hosts can supply a separately verified binary with `-HysteriaPath` or set
`HYSTERIA_BIN` and run the ignored `hysteria2_interop` tests directly.

- Release: https://github.com/HyNetworks/hysteria/releases/tag/app/v2.6.4
- Commit: `2146852c483b7e4f68f405023034b8241bfc49c6`.
- Windows amd64 executable SHA-256: `02bb3681c28789132989de8d13ac3cbf3de7127a75967d4b9595f557216ca8bc`.
- Linux amd64 executable SHA-256: `9836e68e2852fa748e291acaf016a2fa9509efa20e66a3efa585dd8af90b4615`.

On Windows x64, 2026-09-12, the three oracle suites passed: TCP transfers through
256 KiB; UDP through 4,000 bytes with fragmentation in both directions; IPv4/IPv6;
Salamander; incorrect password/obfuscation key; untrusted certificate; unreachable
TCP target; new connections after rejected authentication and actual server
restart; disabled UDP; negotiated upload pacing and server-forced automatic mode.
The hopping fixture uses two loopback port forwards and preserves one TCP stream
across two timed hops while also exchanging UDP traffic.

The pinned server uses a 4,096-byte UDP buffer including encoded messages, so
this record does not claim 65,507-byte end-to-end official interoperability.
Unit tests cover golden bytes, truncated input, reordered/duplicate/inconsistent
fragments, invalid indices, shared memory release and expiration. The separate
`hysteria2_frames` ASan/libFuzzer target exercises decoding, reassembly and
Salamander; see `fuzz/README.md`.

ASan/libFuzzer found an IPv6 textual normalization assertion (the same address
spelled `a::0` and `a::`). Target parsing now canonicalizes IP literals and
rejects ambiguous authorities, userinfo and invalid bracketed names, with a
permanent regression vector. The final parser passed 653,100 fuzz inputs in
61 seconds on Ubuntu 22.04 WSL; an earlier normalization pass also completed
1,188,211 inputs without failure.

Protocol reference: the public wire layout and pinned official source above.
No external proxy source was copied or linked. Desktop TUN, network switching,
mobile integration and the rest of the rewrite have separate acceptance criteria.
