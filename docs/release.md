# Local Release Packaging

PowerShell 7, tar, Rust 1.93.1 and the host C/linker toolchain are required.
Desktop packages contain the CLI, C ABI static/dynamic libraries, C header,
examples, documentation, project license and dependency license notices.
`dependencies.json` inventories resolved foundation packages, including test and
optional packages; it does not claim that all of them are linked into the binary.
`release-manifest.json` records the target, lockfile hash and every payload hash.
Each archive has a separate SHA-256 record. Scripts create only local artifacts.
Three registry packages omit license texts: asn1-rs-impl 0.2.0, defmt 0.3.100 and
defmt-parser 1.0.0. Packaging includes notices from their matching archived upstream
workspace crates; `notice_source` records each source. Unaccounted missing notices
fail packaging rather than producing an empty license directory.

```powershell
cargo fetch --locked
./scripts/package-release.ps1
```

This performs a locked offline release build and creates a unique directory and
`.tar.gz` under ignored `dist/`. Optional `-Target` selects an installed desktop
target with a working linker; a cross-build does not run that platform's tests.
macOS native builds default to deployment target 12.0. Windows packages require
the official signed x64 Wintun DLL separately for TUN operation; it is not bundled.

For a release backed by archived dependency sources, prepare an offline snapshot
with `prepare-offline.ps1`, extract it, verify it with `verify-offline.ps1`, then
run the extracted `scripts/package-release.ps1`. Set `CARGO_TARGET_DIR` to the
verifier's reported build directory to reuse verified release objects and supply
`-OutputDirectory` outside the extracted source. The release manifest records
the source snapshot manifest hash. Retain the matching source archive, archive
checksums and build records with the binary package for distribution.

Mobile hosts build their libraries separately:

```powershell
./scripts/check-mobile.ps1 -Platform android -Ndk PATH_TO_NDK -Release
./scripts/check-mobile.ps1 -Platform ios -Release
```

Android uses NDK 27.0.12077973 / API 24; iOS requires macOS/Xcode and an installed
iPhoneOS SDK. The script restores compiler environment variables on success and
failure. Libraries appear in the target-specific `release/` directory. Include
`crates/ffi/include/meta_rust.h` in the host integration. These commands validate
compilation, not mobile application or VPN runtime behavior.

`.github/workflows/rust.yml` runs local tests, formatting, strict Clippy and release
packaging on Windows, Linux and Intel/Apple Silicon macOS. Separate jobs build
iOS arm64 on macOS and Android arm64 with the pinned NDK on Linux. The workflow
has no artifact upload, remote release or publication step. Native privileged
TUN tests and external protocol oracles require their documented prerequisites.
