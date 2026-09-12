#Requires -Version 7.0
param([ValidateSet('android', 'ios')][string]$Platform, [string]$Ndk)
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $workspace
try {
    if ($Platform -eq 'android') {
        if (-not $Ndk) { $Ndk = $env:ANDROID_NDK_HOME }
        if (-not $Ndk) { throw 'Supply -Ndk or ANDROID_NDK_HOME.' }
        $hostTag = if ($IsWindows) { 'windows-x86_64' } elseif ($IsMacOS) { 'darwin-x86_64' } else { 'linux-x86_64' }
        $bin = Join-Path $Ndk "toolchains/llvm/prebuilt/$hostTag/bin"
        $suffix = if ($IsWindows) { '.cmd' } else { '' }
        $env:CC_aarch64_linux_android = Join-Path $bin "aarch64-linux-android24-clang$suffix"
        $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $env:CC_aarch64_linux_android
        $env:AR_aarch64_linux_android = Join-Path $bin $(if ($IsWindows) { 'llvm-ar.exe' } else { 'llvm-ar' })
        cargo build -p meta-ffi --target aarch64-linux-android --locked --offline
    } else {
        if (-not $IsMacOS) { throw 'iOS compilation requires macOS with Xcode and the iPhoneOS SDK.' }
        $env:IPHONEOS_DEPLOYMENT_TARGET = '12.0'
        cargo build -p meta-ffi --target aarch64-apple-ios --locked --offline
    }
    if ($LASTEXITCODE -ne 0) { throw 'Mobile core/FFI build failed.' }
} finally { Pop-Location }
