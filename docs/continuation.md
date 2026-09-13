# Continuation Ledger

This is the current task ledger. Update each row and append evidence immediately
after completing an item. Keep source revisions, commands, results and artifact
hashes in Git; generated binaries/logs under ignored `target/` and `dist/` must be
transferred separately when moving machines. Never infer success from an
interrupted session or substitute cross-compilation for runtime acceptance.

## Tasks

| ID | Task | Status |
| --- | --- | --- |
| T1 | Complete workspace tests after oversized UDP fix | Complete at baseline `9e4ac576`: Windows/Linux each 54 passed, 6 ignored |
| T2 | Verify source snapshot `607ae268` offline on Windows/Linux | Complete: Windows/Linux empty-cache offline release builds |
| T3 | Refresh and verify packaged binaries from verified source | Complete for baseline `9e4ac576`; new deployment fixes require a subsequent snapshot |
| T4 | Windows route plus interface metric selection | Complete; Windows unit/live interface query tests passed |
| T5 | Cancel in-progress HY2 establishment on network changes | Complete; Windows/Linux cancellation regression passed |
| T6 | Desktop full routing/DNS/network-switch/recovery acceptance | Needs privileged Windows/Wintun and macOS; Linux integration can run locally |
| T7 | iOS arm64 build and macOS build matrix | Needs Mac/Xcode/iPhoneOS SDK |

## Evidence

### 2026-09-13 Start

- Implementation baseline `9e4ac576`; documentation baseline `f6219610`.
- Branch `meta-rust`; initially clean; `Alpha` must remain unchanged.
- Linux command: `cargo test --workspace --locked --offline`, Rust 1.93.1,
  Ubuntu-22.04 WSL, target directory `/home/adoom/meta-rust-platform-target`.
  Process exit 0; log `target/continuation-workspace-linux.log`.
- Windows command: same, log `target/continuation-workspace-windows.log`;
  completion is pending at this checkpoint.
- Current Windows token is not administrator; `target/release/wintun.dll` absent.
  Do not mark Windows native TUN acceptance passed on this host.

### T1 Complete - 2026-09-13

- Both commands exited 0: Windows x64 MSVC and Linux x64 GNU (Ubuntu-22.04 WSL),
  Rust 1.93.1, `cargo test --workspace --locked --offline`.
- Each host: 54 passed, 0 failed, 6 ignored. The six require external oracle
  executables or a privileged TUN device; no runtime acceptance is inferred.
- Logs: `target/continuation-workspace-windows.log` and
  `target/continuation-workspace-linux.log`. Tested implementation `9e4ac576`;
  subsequent deployment fixes will have their own checks and source archive.
- T2 Linux verification also exited 0: extracted source `607ae268`, empty cache
  and target, locked offline release build, executable checks and 54 local tests.
  Log: `target/continuation-offline-linux.log`; archive-side build/test/result logs
  remain beside `dist/meta-rust-offline-607ae268.tar.gz`.
### T2/T3 Complete - 2026-09-13

- Windows verifier result confirms 18,767 snapshot hashes, empty initial Cargo
  home/target and successful locked offline release build on Rust 1.93.1.
  Log: `target/continuation-offline-windows.log`.
- Verified executable SHA256:
  `5fbbe63735546049f9953fc161134575a94d4fc8a08fd18ce5a591d0c6c37e11`.
- Packaged extracted snapshot `607ae268` using its verified build directory:
  `dist/meta-rust-0.1.0-x86_64-pc-windows-msvc-43fbc8d1.tar.gz`.
  SHA256: `b7ad2117ef36b6bdc1c7f97504f6a8f9bee681cacef99986068eb01084028ac0`.
- All 554 package payload hashes verified; CLI version and both VLESS/HY2
  example configuration checks passed. Log: `target/continuation-package-windows.log`.
  This package contains baseline `9e4ac576`, not the following T4/T5 fixes.

### T4/T5 Complete - 2026-09-13

- Windows default-route ordering now adds the address-family-specific interface
  metric to route metric using u64; unreadable candidates are excluded.
  Tests cover family differences, overflow and a live OS interface query.
- HY2 establishment and lock waiters observe a network-generation cancellation
  token and core shutdown. Network changes invalidate old cached clients without
  waiting for ongoing handshakes or removing clients from the new generation.
- Regression uses a real nonresponding local QUIC endpoint: cancels pending
  establishment and lock waiter, permits a fresh attempt, then cancels on stop.
- `cargo test -p meta-core -p meta-platform --locked --offline`: Windows 18
  passed, Linux 16 passed; native TUN test ignored on each. Logs:
  `target/continuation-network-tests.log`, `target/continuation-network-linux.log`.
- Remaining delivery work: archive and package a new snapshot incorporating these
  fixes; full privileged desktop acceptance and Apple builds remain outstanding.
- `cargo fmt --all`, `git diff --check` and Windows
  `cargo clippy -p meta-core -p meta-platform --all-targets --locked --offline -- -D warnings`
  passed; Clippy log: `target/continuation-network-clippy.log`.
