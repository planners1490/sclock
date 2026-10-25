// scLock Rust Workspace build.rs Integration Template
// Links the scLock-emitted static SEP runtime archive (`libsys_color_rt.a`) and Apple CryptoKit.

use std::process::Command;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let sdk_out = Command::new("xcrun")
        .arg("--show-sdk-path")
        .output()
        .expect("Failed to locate macOS SDK via xcrun");
    let sdk_path = String::from_utf8_lossy(&sdk_out.stdout).trim().to_string();
    let toolchain_swift_lib =
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx";

    println!("cargo:rerun-if-changed=libsys_color_rt.a");
    println!("cargo:rustc-link-search=native={}", manifest_dir);
    println!("cargo:rustc-link-lib=static=sys_color_rt");
    println!("cargo:rustc-link-search=native={}", toolchain_swift_lib);
    println!("cargo:rustc-link-search=native={}/usr/lib/swift", sdk_path);
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=CryptoKit");
}
