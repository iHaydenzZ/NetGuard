//! Windows Shell32/GDI icon extraction for process executables (AC-1.6).
//!
//! Extracts the small icon from an executable using `ExtractIconExW`,
//! converts it to a 32-bit BMP, and returns a base64 data URI.

use base64::Engine as _;

/// Log a warning when a GDI/User32 cleanup call returns failure (0).
fn warn_gdi_cleanup(func_name: &str, handle: usize, result: i32) {
    if result == 0 {
        tracing::warn!(
            func = func_name,
            handle,
            "GDI cleanup call failed (returned 0)"
        );
    }
}

/// Extract a process icon from an executable path and return it as a
/// `data:image/bmp;base64,...` URI string, or `None` if extraction fails.
pub fn extract_icon(exe_path: &str) -> Option<String> {
    use win_icon_api::*;

    let wide: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();

    let mut h_small: usize = 0;
    let count = unsafe { ExtractIconExW(wide.as_ptr(), 0, std::ptr::null_mut(), &mut h_small, 1) };
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
                warn_gdi_cleanup(
                    "DeleteObject(hbmMask)",
                    icon_info.hbmMask,
                    DeleteObject(icon_info.hbmMask),
                );
                warn_gdi_cleanup(
                    "DeleteObject(hbmColor)",
                    icon_info.hbmColor,
                    DeleteObject(icon_info.hbmColor),
                );
            }
            return None;
        }

        let width = bm.bmWidth;
        let height = bm.bmHeight;
        if width <= 0 || height <= 0 || width > 256 || height > 256 {
            unsafe {
                warn_gdi_cleanup(
                    "DeleteObject(hbmMask)",
                    icon_info.hbmMask,
                    DeleteObject(icon_info.hbmMask),
                );
                warn_gdi_cleanup(
                    "DeleteObject(hbmColor)",
                    icon_info.hbmColor,
                    DeleteObject(icon_info.hbmColor),
                );
            }
            return None;
        }

        let hdc = unsafe { CreateCompatibleDC(0) };
        if hdc == 0 {
            unsafe {
                warn_gdi_cleanup(
                    "DeleteObject(hbmMask)",
                    icon_info.hbmMask,
                    DeleteObject(icon_info.hbmMask),
                );
                warn_gdi_cleanup(
                    "DeleteObject(hbmColor)",
                    icon_info.hbmColor,
                    DeleteObject(icon_info.hbmColor),
                );
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
            warn_gdi_cleanup("DeleteDC", hdc, DeleteDC(hdc));
            warn_gdi_cleanup(
                "DeleteObject(hbmMask)",
                icon_info.hbmMask,
                DeleteObject(icon_info.hbmMask),
            );
            warn_gdi_cleanup(
                "DeleteObject(hbmColor)",
                icon_info.hbmColor,
                DeleteObject(icon_info.hbmColor),
            );
        }

        if scan_ret == 0 {
            return None;
        }

        Some(build_bmp_data_uri(&pixels, width, height))
    })();

    unsafe {
        warn_gdi_cleanup("DestroyIcon", h_small, win_icon_api::DestroyIcon(h_small));
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

    /// Decode the base64 BMP URI produced by `build_bmp_data_uri` into raw bytes.
    fn decode_bmp_uri(uri: &str) -> Vec<u8> {
        let b64 = uri.strip_prefix("data:image/bmp;base64,").unwrap();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
    }

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
        let decoded = decode_bmp_uri(&uri);
        let expected_size = 14 + 40 + (16 * 16 * 4);
        assert_eq!(decoded.len(), expected_size);
        // Verify BMP signature
        assert_eq!(&decoded[0..2], b"BM");
    }

    /// The BMP file header (bytes 0-13) and DIB header (bytes 14-53) must encode
    /// the correct dimensions, pixel data offset, bit depth, and sizes.
    ///
    /// BMP file header layout (14 bytes):
    ///   [0..2]  "BM" signature
    ///   [2..6]  file size (u32 LE)
    ///   [6..8]  reserved (0)
    ///   [8..10] reserved (0)
    ///   [10..14] pixel data offset from file start (u32 LE) = 54 (14+40)
    ///
    /// BITMAPINFOHEADER layout (40 bytes, starting at offset 14):
    ///   [14..18] header size = 40 (u32 LE)
    ///   [18..22] width (i32 LE)
    ///   [22..26] height (i32 LE, positive = bottom-up)
    ///   [26..28] planes = 1 (u16 LE)
    ///   [28..30] bit count = 32 (u16 LE)
    ///   [30..34] compression = 0 (u32 LE)
    ///   [34..38] pixel data size (u32 LE)
    ///   [38..42] x pixels per meter = 0
    ///   [42..46] y pixels per meter = 0
    ///   [46..50] clr used = 0
    ///   [50..54] clr important = 0
    #[test]
    fn test_build_bmp_data_uri_header_fields() {
        let w: i32 = 32;
        let h: i32 = 32;
        let pixels = vec![0u8; (w * h * 4) as usize];
        let uri = build_bmp_data_uri(&pixels, w, h);
        let bmp = decode_bmp_uri(&uri);

        let pixel_data_size = (w * h * 4) as u32;
        let file_size = 14u32 + 40 + pixel_data_size;

        // File header
        assert_eq!(&bmp[0..2], b"BM");
        assert_eq!(u32::from_le_bytes(bmp[2..6].try_into().unwrap()), file_size);
        assert_eq!(u16::from_le_bytes(bmp[6..8].try_into().unwrap()), 0); // reserved
        assert_eq!(u16::from_le_bytes(bmp[8..10].try_into().unwrap()), 0); // reserved
        assert_eq!(u32::from_le_bytes(bmp[10..14].try_into().unwrap()), 54); // pixel offset

        // DIB header
        assert_eq!(u32::from_le_bytes(bmp[14..18].try_into().unwrap()), 40); // header size
        assert_eq!(i32::from_le_bytes(bmp[18..22].try_into().unwrap()), w);
        assert_eq!(i32::from_le_bytes(bmp[22..26].try_into().unwrap()), h); // positive = bottom-up
        assert_eq!(u16::from_le_bytes(bmp[26..28].try_into().unwrap()), 1); // planes
        assert_eq!(u16::from_le_bytes(bmp[28..30].try_into().unwrap()), 32); // bit depth
        assert_eq!(u32::from_le_bytes(bmp[30..34].try_into().unwrap()), 0); // compression (BI_RGB)
        assert_eq!(
            u32::from_le_bytes(bmp[34..38].try_into().unwrap()),
            pixel_data_size
        );
        assert_eq!(i32::from_le_bytes(bmp[38..42].try_into().unwrap()), 0);
        assert_eq!(i32::from_le_bytes(bmp[42..46].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bmp[46..50].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bmp[50..54].try_into().unwrap()), 0);
    }

    /// `build_bmp_data_uri` receives top-down pixel data (row 0 = top) from
    /// `GetDIBits` (because we pass a negative height to `BITMAPINFOHEADER`) but
    /// writes the BMP with a positive height, which requires bottom-up row order.
    /// Verify that rows are reversed: the first BMP pixel row (at offset 54) is
    /// the last row of the input, and the last BMP row is the first row of input.
    #[test]
    fn test_build_bmp_data_uri_pixel_rows_are_reversed() {
        // 2x2 image: 4 pixels, each BGRA = 4 bytes. Total = 16 bytes.
        // Row 0 (top) = two red pixels (BGRA: 0x00, 0x00, 0xFF, 0xFF)
        // Row 1 (bottom) = two blue pixels (BGRA: 0xFF, 0x00, 0x00, 0xFF)
        let red_pixel = [0x00u8, 0x00, 0xFF, 0xFF]; // BGRA red
        let blue_pixel = [0xFF, 0x00, 0x00, 0xFF]; // BGRA blue
        let mut pixels = Vec::with_capacity(16);
        pixels.extend_from_slice(&red_pixel);
        pixels.extend_from_slice(&red_pixel);
        pixels.extend_from_slice(&blue_pixel);
        pixels.extend_from_slice(&blue_pixel);

        let uri = build_bmp_data_uri(&pixels, 2, 2);
        let bmp = decode_bmp_uri(&uri);

        // BMP pixel data starts at offset 54 (= 14 + 40).
        // Bottom-up order means row 1 (blue) is written first, then row 0 (red).
        let pixel_data = &bmp[54..];
        // First 8 bytes = row 1 (blue, reversed from top-down input)
        assert_eq!(
            &pixel_data[0..4],
            &blue_pixel,
            "first BMP row should be input row 1"
        );
        assert_eq!(
            &pixel_data[4..8],
            &blue_pixel,
            "first BMP row pixel 2 should be blue"
        );
        // Next 8 bytes = row 0 (red, top row of input is last in BMP)
        assert_eq!(
            &pixel_data[8..12],
            &red_pixel,
            "second BMP row should be input row 0"
        );
        assert_eq!(
            &pixel_data[12..16],
            &red_pixel,
            "second BMP row pixel 2 should be red"
        );
    }

    /// A 1x1 image exercises the minimal code path and validates that single-pixel
    /// BMP output is exactly 54 + 4 = 58 bytes with the correct pixel value.
    #[test]
    fn test_build_bmp_data_uri_single_pixel() {
        // One green pixel in BGRA: B=0x00, G=0xFF, R=0x00, A=0xFF.
        let green = [0x00u8, 0xFF, 0x00, 0xFF];
        let uri = build_bmp_data_uri(&green, 1, 1);
        let bmp = decode_bmp_uri(&uri);

        assert_eq!(bmp.len(), 58); // 14 + 40 + 4
        assert_eq!(&bmp[54..58], &green);
    }
}
