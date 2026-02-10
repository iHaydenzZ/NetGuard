fn main() {
    let mut attrs = tauri_build::Attributes::new();

    #[cfg(target_os = "windows")]
    {
        let windows = tauri_build::WindowsAttributes::new().app_manifest(
            r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>"#,
        );
        attrs = attrs.windows_attributes(windows);
    }

    tauri_build::try_build(attrs).expect("failed to run tauri_build");

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
