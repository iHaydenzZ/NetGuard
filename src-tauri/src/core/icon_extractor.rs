//! Windows Shell32/GDI icon extraction for process executables (AC-1.6).
//!
//! Extracts the small icon from an executable using `ExtractIconExW`,
//! converts it to a 32-bit BMP, and returns a base64 data URI.

use base64::Engine as _;

/// Extract a process icon from an executable path and return it as a
/// `data:image/bmp;base64,...` URI string, or `None` if extraction fails.
pub fn extract_icon(exe_path: &str) -> Option<String> {
    use win_icon_api::*;

    let wide: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();

    let mut h_small: usize = 0;
    let count =
        unsafe { ExtractIconExW(wide.as_ptr(), 0, std::ptr::null_mut(), &mut h_small, 1) };
    if count == 0 || h_small == 0 {
        tracing::trace!("No icon found for {exe_path}");
        return None;
    }

    let result = (|| -> Option<String> {
        let mut icon_info: ICONINFO = unsafe { std::mem::zeroed() };
        if unsafe { GetIconInfo(h_small, &mut icon_info) } == 0 {
            return None;
        }

        let mut bm: BITMAP = unsafe { std::mem::zeroed() };
        let obj_ret = unsafe {
            GetObjectW(
                icon_info.hbmColor,
                std::mem::size_of::<BITMAP>() as i32,
                &mut bm as *mut BITMAP as *mut u8,
            )
        };
        if obj_ret == 0 {
            unsafe {
                DeleteObject(icon_info.hbmMask);
                DeleteObject(icon_info.hbmColor);
            }
            return None;
        }

        let width = bm.bmWidth;
        let height = bm.bmHeight;
        if width <= 0 || height <= 0 || width > 256 || height > 256 {
            unsafe {
                DeleteObject(icon_info.hbmMask);
                DeleteObject(icon_info.hbmColor);
            }
            return None;
        }

        let hdc = unsafe { CreateCompatibleDC(0) };
        if hdc == 0 {
            unsafe {
                DeleteObject(icon_info.hbmMask);
                DeleteObject(icon_info.hbmColor);
            }
            return None;
        }

        let mut bmi: BITMAPINFO = unsafe { std::mem::zeroed() };
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = width;
        bmi.bmiHeader.biHeight = -height; // negative = top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = 0; // BI_RGB

        let pixel_count = (width * height) as usize;
        let mut pixels = vec![0u8; pixel_count * 4]; // BGRA

        let scan_ret = unsafe {
            GetDIBits(
                hdc,
                icon_info.hbmColor,
                0,
                height as u32,
                pixels.as_mut_ptr(),
                &mut bmi,
                0, // DIB_RGB_COLORS
            )
        };

        unsafe {
            DeleteDC(hdc);
            DeleteObject(icon_info.hbmMask);
            DeleteObject(icon_info.hbmColor);
        }

        if scan_ret == 0 {
            return None;
        }

        Some(build_bmp_data_uri(&pixels, width, height))
    })();

    unsafe {
        win_icon_api::DestroyIcon(h_small);
    }

    result
}

/// Build a BMP file in memory from raw BGRA pixel data and return a base64 data URI.
fn build_bmp_data_uri(pixels: &[u8], width: i32, height: i32) -> String {
    let row_bytes = (width as usize) * 4;
    let pixel_data_size = row_bytes * (height as usize);
    let file_size = 14 + 40 + pixel_data_size;
    let mut bmp = Vec::with_capacity(file_size);

    // BMP File Header (14 bytes)
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&(file_size as u32).to_le_bytes());
    bmp.extend_from_slice(&0u16.to_le_bytes());
    bmp.extend_from_slice(&0u16.to_le_bytes());
    bmp.extend_from_slice(&54u32.to_le_bytes());

    // DIB Header (BITMAPINFOHEADER, 40 bytes)
    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&width.to_le_bytes());
    bmp.extend_from_slice(&height.to_le_bytes()); // positive = bottom-up
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&32u16.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&(pixel_data_size as u32).to_le_bytes());
    bmp.extend_from_slice(&0i32.to_le_bytes());
    bmp.extend_from_slice(&0i32.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());

    // Pixel data (bottom-up row order for BMP)
    for y in (0..height as usize).rev() {
        let row_start = y * row_bytes;
        bmp.extend_from_slice(&pixels[row_start..row_start + row_bytes]);
    }

    let encoded = base64::engine::general_purpose::STANDARD.encode(&bmp);
    format!("data:image/bmp;base64,{encoded}")
}

// ---------------------------------------------------------------------------
// Windows FFI for Shell32/GDI icon extraction
// ---------------------------------------------------------------------------

#[allow(non_snake_case)]
mod win_icon_api {
    #[link(name = "shell32")]
    extern "system" {
        pub fn ExtractIconExW(
            lpszFile: *const u16,
            nIconIndex: i32,
            phiconLarge: *mut usize,
            phiconSmall: *mut usize,
            nIcons: u32,
        ) -> u32;
    }

    #[link(name = "user32")]
    extern "system" {
        pub fn DestroyIcon(hIcon: usize) -> i32;
        pub fn GetIconInfo(hIcon: usize, piconinfo: *mut ICONINFO) -> i32;
    }

    #[link(name = "gdi32")]
    extern "system" {
        pub fn GetDIBits(
            hdc: usize,
            hbm: usize,
            start: u32,
            cLines: u32,
            lpvBits: *mut u8,
            lpbmi: *mut BITMAPINFO,
            usage: u32,
        ) -> i32;
        pub fn CreateCompatibleDC(hdc: usize) -> usize;
        pub fn DeleteDC(hdc: usize) -> i32;
        pub fn DeleteObject(ho: usize) -> i32;
        pub fn GetObjectW(h: usize, c: i32, pv: *mut u8) -> i32;
    }

    #[repr(C)]
    #[allow(clippy::upper_case_acronyms)]
    pub struct ICONINFO {
        pub fIcon: i32,
        pub xHotspot: u32,
        pub yHotspot: u32,
        pub hbmMask: usize,
        pub hbmColor: usize,
    }

    #[repr(C)]
    #[allow(clippy::upper_case_acronyms)]
    pub struct BITMAPINFOHEADER {
        pub biSize: u32,
        pub biWidth: i32,
        pub biHeight: i32,
        pub biPlanes: u16,
        pub biBitCount: u16,
        pub biCompression: u32,
        pub biSizeImage: u32,
        pub biXPelsPerMeter: i32,
        pub biYPelsPerMeter: i32,
        pub biClrUsed: u32,
        pub biClrImportant: u32,
    }

    #[repr(C)]
    #[allow(clippy::upper_case_acronyms)]
    pub struct BITMAPINFO {
        pub bmiHeader: BITMAPINFOHEADER,
        pub bmiColors: [u32; 1],
    }

    #[repr(C)]
    #[allow(clippy::upper_case_acronyms)]
    pub struct BITMAP {
        pub bmType: i32,
        pub bmWidth: i32,
        pub bmHeight: i32,
        pub bmWidthBytes: i32,
        pub bmPlanes: u16,
        pub bmBitsPixel: u16,
        pub bmBits: *mut u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_bmp_data_uri_format() {
        let pixels = vec![0u8; 4 * 4]; // 2x2 black BGRA image
        let uri = build_bmp_data_uri(&pixels, 2, 2);
        assert!(uri.starts_with("data:image/bmp;base64,"));
    }

    #[test]
    fn test_build_bmp_data_uri_correct_file_size() {
        let pixels = vec![0xFFu8; 16 * 16 * 4]; // 16x16 image
        let uri = build_bmp_data_uri(&pixels, 16, 16);
        let b64_part = uri.strip_prefix("data:image/bmp;base64,").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64_part).unwrap();
        let expected_size = 14 + 40 + (16 * 16 * 4);
        assert_eq!(decoded.len(), expected_size);
        // Verify BMP signature
        assert_eq!(&decoded[0..2], b"BM");
    }
}
