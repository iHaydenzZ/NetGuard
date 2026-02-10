fn main() {
    tauri_build::build();

    // Copy WinDivert runtime files (DLL + kernel driver) next to the output binary.
    // Both files are vendored from the official WinDivert 2.2.2 release to ensure
    // version compatibility between the user-mode DLL and signed kernel driver.
    #[cfg(target_os = "windows")]
    {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        // OUT_DIR is e.g. target/debug/build/netguard-xxx/out
        // Walk up to target/debug/ (or target/release/).
        let target_dir = out_dir
            .ancestors()
            .nth(3)
            .expect("could not determine target dir");

        for file in &["WinDivert.dll", "WinDivert64.sys"] {
            let src = std::path::Path::new("vendor/windivert").join(file);
            if src.exists() {
                let dst = target_dir.join(file);
                std::fs::copy(&src, &dst)
                    .unwrap_or_else(|e| panic!("failed to copy {file} to target dir: {e}"));
                println!("cargo:warning=Copied {file} to {}", dst.display());
            }
        }

        println!("cargo:rerun-if-changed=vendor/windivert/WinDivert.dll");
        println!("cargo:rerun-if-changed=vendor/windivert/WinDivert64.sys");
    }
}
