//! The port the "TLS on a port" Check dials: a chip for each common TLS port, or one the rep types.

pub const PRESETS: [u16; 5] = [443, 465, 993, 995, 8443];

pub const INVALID: &str = "Type a whole port number from 1 to 65535.";

pub fn preset_label(port: u16) -> String {
    let service = match port {
        443 => "HTTPS",
        465 => "SMTPS",
        993 => "IMAPS",
        995 => "POP3S",
        8443 => "alternate HTTPS",
        _ => return port.to_string(),
    };
    format!("{port} {service}")
}

/// Digits only: a sign, a space or a decimal point is a typo, not a port.
pub fn parse_port(text: &str) -> Result<u16, &'static str> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(INVALID);
    }
    text.parse::<u16>().ok().filter(|&p| p >= 1).ok_or(INVALID)
}

/// What the tab holds: the port that will run, and why the typed text cannot be one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortChoice {
    port: u16,
    error: Option<&'static str>,
    text: String,
}

impl Default for PortChoice {
    fn default() -> Self {
        PortChoice { port: PRESETS[0], error: None, text: String::new() }
    }
}

impl PortChoice {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn error(&self) -> Option<&'static str> {
        self.error
    }

    /// What the text field holds, so a tab keeps its own when the rep switches away and back.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// A chip was picked: the typed text no longer applies.
    pub fn choose(&mut self, port: u16) {
        *self = PortChoice { port, error: None, text: String::new() };
    }

    /// The text field changed. Empty text keeps the port that was chosen; a bad one blocks the run.
    pub fn typed(&mut self, text: &str) {
        self.text = text.to_string();
        if text.trim().is_empty() {
            self.error = None;
            return;
        }
        match parse_port(text) {
            Ok(port) => (self.port, self.error) = (port, None),
            Err(e) => self.error = Some(e),
        }
    }

    /// The port to dial, or the reason there is none.
    pub fn to_run(&self) -> Result<u16, &'static str> {
        self.error.map_or(Ok(self.port), Err)
    }

    /// The chip that is on: a typed port that is not a preset leaves every chip off.
    pub fn is_preset(&self) -> bool {
        PRESETS.contains(&self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_is_a_whole_number_from_1_to_65535() {
        for ok in ["1", "443", " 8443 ", "65535", "0080"] {
            assert!(parse_port(ok).is_ok(), "{ok}");
        }
        for bad in
            ["", " ", "0", "65536", "-1", "+443", "44 3", "443.0", "https", "4e3", "１２３", "99999999999999999999"]
        {
            assert_eq!(parse_port(bad), Err(INVALID), "{bad:?}");
        }
        assert_eq!(parse_port("0080"), Ok(80));
    }

    #[test]
    fn the_default_is_443_and_the_five_chips_are_the_common_tls_ports() {
        assert_eq!(PortChoice::default().to_run(), Ok(443));
        assert_eq!(PRESETS, [443, 465, 993, 995, 8443]);
        assert_eq!(preset_label(993), "993 IMAPS");
    }

    #[test]
    fn a_typed_port_replaces_the_chip_and_leaves_every_chip_off_when_it_is_not_one() {
        let mut c = PortChoice::default();
        c.typed("8080");
        assert_eq!((c.to_run(), c.is_preset()), (Ok(8080), false));
        c.typed("995");
        assert_eq!((c.to_run(), c.is_preset()), (Ok(995), true));
    }

    #[test]
    fn a_bad_typed_port_blocks_the_run_instead_of_running_the_old_one() {
        let mut c = PortChoice::default();
        c.choose(993);
        c.typed("70000");
        assert_eq!(c.to_run(), Err(INVALID));
        c.typed("993");
        assert_eq!(c.to_run(), Ok(993));
    }

    #[test]
    fn clearing_the_field_returns_to_the_chosen_port_and_a_chip_clears_a_bad_field() {
        let mut c = PortChoice::default();
        c.choose(465);
        c.typed("nope");
        c.typed("");
        assert_eq!(c.to_run(), Ok(465));
        c.typed("nope");
        c.choose(443);
        assert_eq!((c.to_run(), c.error()), (Ok(443), None));
        assert_eq!(c.text(), "");
    }

    #[test]
    fn the_tab_remembers_what_was_typed() {
        let mut c = PortChoice::default();
        c.typed("80x");
        assert_eq!(c.text(), "80x");
    }
}
