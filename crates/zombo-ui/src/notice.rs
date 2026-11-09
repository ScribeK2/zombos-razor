use zombo_core::text::strip;

use crate::settings_model::Settings;

const SUMMARY: &str = "Watch stopped";

/// The desktop notification for a stopped Watch, or `None` when the rep turned them off.
pub fn watch_notice(settings: &Settings, message: &str) -> Option<(&'static str, String)> {
    settings.notifications.then(|| (SUMMARY, strip(message)))
}

/// Send it and carry on. A desktop with no notification service is not an error for the app, so
/// the failure is dropped; the in-app toast already told the rep. The call runs on its own
/// thread because a missing or slow service must never stall the window.
pub fn send(summary: &'static str, body: String) {
    let _ = std::thread::Builder::new().name("zombo-notify".into()).spawn(move || {
        let _ = notify_rust::Notification::new().appname("Zombo's Razor").summary(summary).body(&body).show();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_notice_is_made_only_when_the_setting_is_on() {
        let on = Settings::default();
        let off = Settings { notifications: false, ..Settings::default() };
        assert_eq!(
            watch_notice(&on, "example.com DNS changed").map(|n| n.1).as_deref(),
            Some("example.com DNS changed")
        );
        assert_eq!(watch_notice(&off, "example.com DNS changed"), None);
    }

    #[test]
    fn control_characters_never_reach_the_notification_service() {
        let n = watch_notice(&Settings::default(), "a\u{1b}[31m\nb").unwrap();
        assert!(!n.1.chars().any(zombo_core::text::is_unsafe_char));
    }
}
