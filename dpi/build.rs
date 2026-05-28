fn main() {
    println!("cargo:rerun-if-changed=src/");

    // On Linux, nfq pulls in libnfnetlink transitively; make that explicit so
    // the Go linker can find it when linking against the static library.
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=nfnetlink");
        println!("cargo:rustc-link-lib=mnl");
    }

    // Print the output directory once so `cargo build -v` shows where
    // libflint_dpi.a lands (Go's LDFLAGS need to point there).
    let out = std::env::var("OUT_DIR").unwrap();
    // OUT_DIR is deep inside target/…/build/…; the static lib sits two levels
    // above in target/<profile>/.  Print it as a warning so it surfaces even
    // without -v.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    println!(
        "cargo:warning=libflint_dpi.a → target/{}/libflint_dpi.a  (OUT_DIR={})",
        profile, out
    );
}
