fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=csrc/progress_shim.c");

    // openconnect FFI bindings are only generated on Unix where
    // libopenconnect-dev is available.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        return;
    }

    // Find libopenconnect via pkg-config.
    let lib = match pkg_config::probe_library("openconnect") {
        Ok(lib) => lib,
        Err(e) => {
            println!(
                "cargo:warning=libopenconnect not found ({e}). \
                 Install it with: apt install libopenconnect-dev (Debian/Ubuntu) \
                 or dnf install openconnect-devel (Fedora). \
                 Skipping FFI binding generation."
            );
            // Write an empty bindings file so `include!()` in lib.rs doesn't
            // break the build.
            let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
            std::fs::write(
                out_dir.join("bindings.rs"),
                "// openconnect bindings unavailable — libopenconnect-dev not installed\n",
            )
            .ok();
            return;
        }
    };

    // Generate Rust bindings with bindgen.
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("openconnect_.*")
        .allowlist_type("openconnect_.*")
        .allowlist_type("oc_.*")
        .allowlist_var("OC_.*")
        .allowlist_var("PRG_.*");

    for path in &lib.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }

    let bindings = builder
        .generate()
        .expect("failed to generate openconnect bindings");

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");

    // Compile the C variadic trampoline for openconnect's progress
    // callback. Stable Rust can't implement `extern "C" fn (..., ...)`,
    // so we route through a small C shim that formats the message and
    // forwards to a non-variadic Rust sink.
    cc::Build::new()
        .file("csrc/progress_shim.c")
        .warnings(true)
        .compile("pangolin_progress_shim");
}
