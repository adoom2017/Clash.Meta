# Compatibility Subset

The Go product previously on this branch is retained at `Alpha`, baseline
`3fce2b4fe0eaefd2016f1b60312e1bb991b5c1e3`. Rust regression vectors generated with
Go's standard AES/CFB implementation cover empty, 16/17/24/25/32/40-byte and UTF-8
passwords with the legacy IV, ASCII-zero padding and Base64 encoding. The test
fixtures use synthetic configuration only. No Go compiler is needed by Rust tests.

| Area | Supported |
| --- | --- |
| Nodes | VLESS TCP, TLS, REALITY, Vision, UDP/XUDP; Hysteria 2 TCP/UDP, Salamander, hopping, bandwidth |
| Entrances | HTTP, CONNECT, SOCKS5, mixed, explicitly enabled TUN |
| Rules | DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6, DST-PORT, NETWORK, MATCH; first match |
| Groups | select, url-test; duplicate/cycle/reference validation |
| DNS | UDP/TCP, HTTPS DoH, cache, fake-IP, bootstrap using IP resolvers |
| CLI | -f, -d, -t, -v, -p, --action encrypt/decrypt, --recover-tun |
| Logs | Levels, file rotation/compression and controller log events |
| Hosts | Core lifecycle, PlatformHooks, PacketIo, C ABI v1, Android protect and TUN fd |

Unknown fields and unsupported enum values return a path-aware migration error.
Not included: servers, HY1, WS/gRPC/XHTTP, subscriptions/providers, remote rule
sets, GEOIP/GEOSITE, GUI, VMess, Shadowsocks, Trojan, TUIC, process rules and DoT.
Examples from the old Go product are not silently accepted as full compatibility.

| Controller | Operations |
| --- | --- |
| /version | GET |
| /configs | GET, PATCH mode/rules |
| /proxies | GET |
| /proxies/{name} | GET, PUT selection |
| /proxies/{name}/delay | GET with url and bounded timeout |
| /connections | GET, DELETE all |
| /connections/{id} | DELETE |
| /traffic, /logs | WebSocket GET |

Bearer secret is checked on all routes. Config responses omit node credentials,
controller secret and listener authentication. This API does not promise full
Clash dashboard compatibility. Full config changes restart a newly validated
core; invalid online mode/rule updates apply nothing.

Platform acceptance, including the current Windows/macOS/iOS gaps, is recorded
in `platform-runtime.md`; Linux native IPv4/IPv6 fragmented UDP has been verified.
