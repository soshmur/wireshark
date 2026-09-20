//! Windows only: tell the linker where the Npcap SDK import libraries live.
//! Override with `NPCAP_SDK_LIB=<dir containing wpcap.lib>`.
fn main() {
    println!("cargo:rerun-if-env-changed=NPCAP_SDK_LIB");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        let dir =
            std::env::var("NPCAP_SDK_LIB").unwrap_or_else(|_| r"C:\npcap-sdk\Lib\x64".to_string());
        println!("cargo:rustc-link-search=native={dir}");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
