//! Windows only: delay-load `wpcap.dll` so the binary starts even when Npcap is
//! not installed. The preflight then reports the missing driver instead of the
//! loader failing before `main` runs. Every pcap call is gated behind
//! `netscope_ffi::wpcap_available()` for this reason.
fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
