# meta-rust

Rust proxy core, CLI, desktop TUN adapter and versioned C host API. This branch
replaces the Go product; the previous implementation remains on `Alpha` and in
Git history. The rewrite's acceptance status is in [docs/rust-progress.md](docs/rust-progress.md).

Protocol code is maintained here: VLESS TCP/TLS, REALITY, XTLS Vision, UDP/XUDP;
Hysteria 2 TCP/UDP, Salamander, port hopping and negotiated upload pacing. The
production dependency tree contains general-purpose libraries, no external proxy
core. Xray and official Hysteria binaries are isolated test oracles only.

## Build and Run

Install Rust 1.93.1 with the platform C/C++ compiler. The checked-in toolchain and
Cargo.lock pin the build. Windows targets x64, macOS 12+ targets Intel/Apple
Silicon; Linux is retained. Mobile scope is core/FFI integration interfaces.

```sh
cargo build --release --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
./target/release/meta-rust -f examples/vless.yaml -t
./target/release/meta-rust -f examples/vless.yaml
```

Use `target/release/meta-rust.exe` on Windows. Set actual server credentials in a
configuration based on [examples/vless.yaml](examples/vless.yaml) or
[examples/hysteria2.yaml](examples/hysteria2.yaml). No production server is bundled.

HTTP/CONNECT, SOCKS5 and mixed listeners share rules, select/url-test groups,
DNS/fake-IP and traffic accounting. The reduced controller defaults to loopback;
remote binds require a Bearer secret. Unknown or unsupported fields report a
configuration error. Complete configuration replacement requires a new core;
mode, rules and group selection support online updates.

## Legacy Configuration

`-f`, `-d`, `-t`, `-v`, `-p` and `--action encrypt/decrypt` remain available.
AES-CFB128/Base64 files use the previous byte-length key padding and fixed IV.
This legacy format has no authentication tag; decrypted YAML is validated before
use. Invalid Base64, invalid decrypted configuration and output overwrites fail.

```sh
meta-rust -f config.yaml --action encrypt
meta-rust -f config-encrypt.yaml -p PASSWORD
meta-rust -f config-encrypt.yaml --action decrypt
```

Interactive encryption/decryption prompts for the password when omitted.
Noninteractive callers supply `-p`. Logs support level overrides, bounded file
rotation and controller events without exposing configured credentials.

## Platform and Delivery

- [Desktop TUN and mobile host ABI](docs/platform-runtime.md): privileges,
  physical egress, route recovery, network changes, packet/fd ownership and tests.
- [Compatibility subset](docs/compatibility.md): supported configuration and API.
- [Core runtime](docs/core-runtime.md): lifecycle, resource limits, DNS and updates.
- [VLESS verification](docs/vless-protocol.md) and [HY2 verification](docs/hysteria2-protocol.md).
- [Offline source archives](docs/offline-build.md) and [third-party patches](third-party/README.md).
- [Local release packages](docs/release.md): CLI, host libraries, licenses and hashes.

TUN must be explicitly enabled; desktop use requires root/administrator rights
and Windows additionally needs official `wintun.dll`. An interrupted session can
be restored with `meta-rust -d CONFIG_DIRECTORY --recover-tun`.

Windows/macOS native TUN and iOS compilation still require their stated host
prerequisites. Linux native TUN and Android arm64 compilation have separate test
records; they do not substitute for Windows/macOS or mobile runtime acceptance.
Nothing is automatically pushed or published by local build/package scripts.
