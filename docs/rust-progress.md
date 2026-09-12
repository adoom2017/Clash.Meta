# Rust Rewrite Progress

This records the user-approved plan and remaining work so later sessions can
continue from repository state. Work is on `meta-rust`; do not modify `Alpha` or
push/publish automatically. Prioritize VLESS before completing the remaining plan.

## Scope and Boundaries

Deliver the Rust core, CLI, reduced Clash API, Windows Wintun and macOS utun;
retain Linux support. Mobile scope is host interfaces and iOS/Android arm64 build
verification, not application integration or runtime acceptance.

First release protocols: VLESS TCP/TLS, REALITY, Vision, UDP/XUDP; Hysteria 2
TCP/UDP, Salamander, port hopping, negotiated bandwidth/rate control. Local
entrances: HTTP/CONNECT, SOCKS5, mixed, TUN. Include rules, select/url-test groups,
DNS/fake-IP, legacy encrypted configuration and rotating logs.

No servers, HY1, WS/gRPC/XHTTP, subscriptions, remote rule sets, GEOIP/GEOSITE or GUI.
No external proxy cores in production, directly or indirectly. Generic libraries
are allowed; protocol implementations and minimal TLS patches are locally owned.
Pin the toolchain, lock dependencies, archive source snapshots and verify a clean
offline build for release. Preserve source provenance and third-party licenses.

## Current Milestone: VLESS

- [x] VLESS request encoding, lazy response parsing, TCP/TLS and UDP framing.
- [x] XUDP encoding, bounded parser, cancellation handling and core integration.
- [x] Vision padding, fragmented TLS recognition and independent direct switches.
- [x] REALITY session/certificate authentication and local rustls hooks.
- [x] Local byte-boundary, malformed input, large duplex transfer and TLS tests.
- [x] Core integration tests for SOCKS5/HTTP CONNECT, fake-IP and UDP selection.
- [x] Runnable CLI, configuration example and protocol/patch documentation.
- [x] Fixed-version Xray test fixtures for the main VLESS matrix.
- [x] Execute official Xray v25.9.11 interoperability matrix and resolve failures.
- [x] Expand negative oracle cases, reconnection coverage and protocol fuzzing.
- [x] Finish this VLESS milestone and record it in a local commit.

Verified on Windows x64 on 2026-09-12 against checksum-pinned official Xray
v25.9.11. All 36 workspace tests pass, including both external oracle suites.
Coverage includes authentication failures, server restart, ordinary UDP/XUDP and
TLS/REALITY/Vision. SOCKS UDP removes closed outbound sessions so the next packet
can reconnect. Three ASan/libFuzzer targets ran 20,669,305 inputs in WSL without a
protocol crash. See `vless-protocol.md` for commands, limits and exact coverage.

## Offline Source Milestone

- [x] Locked registry source archive, dependency/license inventory and file hashes.
- [x] Extracted archive builds with empty Cargo cache and target directories on
  Windows x64 and Linux x64 (Ubuntu 22.04 WSL), Rust 1.93.1.
- [x] Offline executable version/configuration checks on both hosts; Linux local
  workspace tests: 34 passed, 2 official-oracle tests intentionally ignored.
- [x] Changed source file rejected by checksum verification before compilation.

`scripts/prepare-offline.ps1` creates the portable source archive; verification
commands and the exact tested archive hash are in `docs/offline-build.md`.
OS compiler/linker and Rust toolchain prerequisites are not bundled. The fuzz
workspace uses a separate toolchain/lockfile and is not part of this archive.

## Remaining Stages

HY2 protocol milestone verified on Windows x64 against official Hysteria v2.6.4:
all three oracle suites pass, including TCP/UDP, IPv4/IPv6, fragmentation,
Salamander, two timed port hops, negotiated bandwidth, negative authentication
and restart. The generic Quinn DATAGRAM cap patch has an independent test.
ASan fuzzing exposed an address normalization assertion, now covered by a fixed
regression; the final parser completed 653,100 inputs. See `hysteria2-protocol.md`.

Core runtime update: TCP and UDP now expose live byte counters, bounded tracked
connections and cancellation cleanup. HTTP forwarding uses the same relay path.
HY2 connection setup locks are per node. Routing/DNS waits are included in dial
timeouts and core cancellation. Controller mode/rule updates validate atomically,
configuration reads reflect current policy and omit local authentication. WebSocket
sends are bounded and respond to pings. DNS caches complete positive/negative
responses (including SOA, flags and remaining TTL), with 4,096 entries / 8 MiB
limits; DoH uses Hyper with bounded bodies. Fake-IP exhaustion returns SERVFAIL
without overflowing or reusing live mappings. Eight core tests and strict
workspace Clippy pass on Windows. Full desktop/FFI acceptance remains below.

1. Finish extracting synthetic legacy compatibility vectors, remove Go product
   sources/build flows after Rust replacement is ready, and commit independently.
2. HY2 protocol validation is complete for the documented oracle matrix. Continue
   platform and full application integration acceptance below.
3. Finish core resource/cancellation handling, live connection statistics, full
   API behavior, DNS cache/bootstrap/fake-IP edge cases, group/rule updates and
   compatibility regressions. Existing implementations are not full acceptance.
4. Implement desktop TUN with a general device library and user-space network
   stack, physical egress binding, exclusions, IPv4/IPv6 and network switching.
   Record/restore routes and DNS, roll back partial startup and provide recovery.
5. Implement versioned C ABI, handle/buffer/callback ownership, PacketIo host
   integration, Android socket protection/TUN fd and iOS packet callbacks. Test
   simulated host lifecycle and cross-build both arm64 targets.
6. Complete Windows/macOS runtime tests, broader Linux checks, dependency audit,
   per-release offline source snapshots, release packaging and compatibility/
   platform documents. The initial Windows/Linux offline snapshot is verified;
   macOS and mobile remain unverified. Cross-compilation does not count as platform
   runtime testing.

TUN and FFI are not implemented yet. The CLI explicitly rejects `tun.enable`;
this error is a temporary guard and does not satisfy the planned TUN deliverable.
The core must remain free of terminal interaction, process exit, system route
commands and a global runtime. Final acceptance requires every first-release
feature; partial milestones must not be presented as the completed rewrite.
