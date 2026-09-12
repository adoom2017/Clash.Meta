# Platform Runtime and Host ABI

## Packet Processing

`Core::start_with_packets` accepts a host `PacketIo` when `tun.enable` is true.
Packets are raw IPv4/IPv6 without a Darwin family prefix. smoltcp 0.12.0 owns TCP
state, checksums, retransmission and IPv4 reassembly. Repository code bridges TCP
and UDP to normal fake-IP restoration, rules, groups, protocols and statistics.
TCP and UDP DNS hijack goes directly to the configured resolver.

Limits: 512 TCP flows, 512 UDP flows, 256 UDP destination sockets, 256 packets per
device queue, 32 KiB per TCP stack buffer, four 8 KiB chunks per TCP direction,
16 datagrams per UDP flow, 30-second incomplete TCP handshake limit, 300-second
TCP idle limit and 120-second UDP idle limit. IPv4 fragment/reassembly buffers
are 65,536 bytes. The IPv6 adapter uses smoltcp wire parsers and its range assembler
for 64 concurrent reassemblies, a 65,535-byte packet limit and 30-second expiry
(approximately 4 MiB total). Overlapping fragments invalidate the whole datagram;
atomic fragments remain independent. Generated oversized IPv6 UDP replies are
fragmented to the configured MTU. IPv6 extension chains are bounded to eight.
Oversized generated UDP replies are dropped without terminating packet delivery;
a regression sends a 65,500-byte IPv6 UDP reply followed by a normal reply.

## Desktop

Windows uses tun-rs/Wintun, macOS tun-rs/utun and Linux the system TUN device.
TUN requires administrator/root privileges. Windows requires the separately
licensed official `wintun.dll` beside the executable. macOS chooses an available
utun device when the default device name is used; explicit names must be `utunN`.

```yaml
tun:
  enable: true
  auto-route: true
  auto-detect-interface: true
  mtu: 1500
  dns-hijack: [any:53]
  route-exclude-address: [192.168.0.0/16]
```

Physical egress discovery ignores TUN/loopback interfaces. Set `tun.interface`
to an OS name, Windows friendly name or index when automatic discovery cannot
select the desired device. IPv4/IPv6 outbound sockets bind their physical
interface before connecting, including proxy-server and DNS sockets. Loopback
destinations stay local. Missing physical egress fails instead of entering TUN.

Automatic routing adds split default routes and routes for known system DNS
addresses; DNS packets are handled by the packet adapter. This path preserves
system DNS settings, so restoration concerns only the routes it adds. Local
loopback stub resolvers and other VPN software need deployment-specific tests.
The three-second network check refreshes physical exits and exclusions, clears
DNS caches and closes existing proxy sessions for reconnect.

A locked journal in the `-d` directory records route intent before changes and
is flushed to storage. Startup failure and ordinary shutdown remove owned routes.
Interrupted sessions retain `meta-rust-tun-state.json`; recover them with:

```powershell
meta-rust -d PATH --recover-tun
```

Recovery checks interface identity so a reused OS index does not target a new
adapter. Use the same directory and elevated privileges. Corrupt journals report
errors rather than executing arbitrary recovery actions.

## Mobile and C Hosts

`crates/ffi/include/meta_rust.h` defines ABI v1. Each checked integer handle owns
an independent runtime; IDs are never reused. Creation validates YAML, start is
one-shot, and stop/destroy join workers and callbacks. No Rust allocation crosses
the ABI: inputs are copied and outputs use caller buffers. Size queries return
`META_BUFFER_TOO_SMALL`; too-small packet reads retain the queued packet.
Errors are thread-local UTF-8 text from `meta_error_v1`.

iOS hosts feed NetworkExtension packets through the bounded read/write functions
and receive packet-ready notifications. Android hosts must supply socket protect;
they may use the same packet queue or call `meta_set_tun_fd_v1` before start.
The fd is duplicated; the host retains the original. Packet queue calls return an
explicit error after fd mode is selected. Hosts manage VPN permission,
routes, DNS and application lifecycle. `meta_network_changed_v1` invalidates
connections and DNS cache after a host network change. Callbacks must return
promptly and may not reenter lifecycle functions; their context must remain valid
until stop/destroy returns. These are integration interfaces, not mobile apps.

## Verification Record

2026-09-12/13, Windows x64 and Ubuntu 22.04 WSL:

- Simulated IP devices: 128 KiB TCP round trips and half-close on IPv4/IPv6;
  4,000-byte fragmented IPv4/IPv6 UDP; DNS/fake-IP hijack. IPv6 regression covers
  out-of-order data, wire headers, overlaps, expiry, truncation and queue limits.
- A real Linux TUN test routed isolated `198.19.254.253/32` and
  `fdfe:dcba:9877::fd/128` through VLESS TCP and 4,000-byte UDP, and verified route
  removal. The original IPv4 case caught a partially-read
  VLESS UDP cancellation issue; a deterministic regression now covers the fix.
- Route fault injection verifies recovery after partial initialization, journal
  persistence, exclusive ownership and preservation of unrelated routes.
- Simulated C host tests cover live ICMP packets, buffer retries, notification
  reentry rejection, no callbacks after stop and independent checked handles.
- Android arm64 builds release static and dynamic FFI libraries with Rust 1.93.1, NDK
  27.0.12077973 and API 24. `scripts/check-mobile.ps1` reproduces the build.
- iOS build attempted on Windows but blocked at ring's C compilation: Xcode
  `xcrun` and iPhoneOS SDK are unavailable. Run the iOS script on a Mac with Xcode.

Windows native TUN is not runtime-verified: the current process lacks administrator
privileges and no Wintun DLL is installed. macOS device/routing/network-switch
acceptance is also unverified. The Linux test is not Windows/macOS acceptance;
Android compilation is not mobile runtime acceptance. See `rust-progress.md`.
