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
| T2 | Verify source snapshot `607ae268` offline on Windows/Linux | Linux complete; Windows in progress |
| T3 | Refresh and verify packaged binaries from verified source | Pending |
| T4 | Windows route plus interface metric selection | Implementation in progress |
| T5 | Cancel in-progress HY2 establishment on network changes | Pending |
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
