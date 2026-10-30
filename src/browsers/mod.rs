pub mod chromium;
pub mod firefox;

use crate::session::Session;

pub fn collect(session: &mut Session) {
    chromium::collect(session);
    firefox::collect(session);
}
