use console::{Color, Style, Term, measure_text_width, style};
use std::io::Write;
use std::time::Duration;

use crate::analyzer::{ECDeviceError, ECError, ErrorCorrelation, StateTransition, WkcErrorDetail};
use ecdump::ec_packet::ECPacketError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerboseLevel {
    Nothing = 0,  // 何も出力しない
    Normal = 1,   // 基本的なエラー情報
    Detailed = 2, // 詳細なエラー情報
    Debug = 3,    // 全ての情報（デバッグ用）
}

impl VerboseLevel {
    pub fn from_u8(level: u8) -> Self {
        match level {
            0 => VerboseLevel::Nothing,
            1 => VerboseLevel::Normal,
            2 => VerboseLevel::Detailed,
            _ => VerboseLevel::Debug,
        }
    }
}

/// Signature of the last displayed event, used for consecutive-dedup.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EventSignature {
    /// A string key that identifies "the same kind of event"
    key: String,
    /// The formatted single-line message (without repeat count)
    base_message: String,
}

pub struct ErrorFormatter {
    verbose: VerboseLevel,
    term: Term,
    /// The signature of the most recently displayed event line.
    last_event: Option<EventSignature>,
    /// How many consecutive times the current event has been displayed.
    repeat_count: usize,
    /// Frame number of the first occurrence of the current repeated event.
    repeat_first_frame: u64,
    /// Timestamp of the first occurrence of the current repeated event.
    repeat_first_ts: Duration,
    /// Frame number of the most recent occurrence.
    repeat_last_frame: u64,
    /// Timestamp of the most recent occurrence.
    repeat_last_ts: Duration,
    /// Number of terminal lines occupied by the last printed repeat/event line.
    last_printed_lines: usize,
}

impl ErrorFormatter {
    pub fn new(verbose_level: u8) -> Self {
        ErrorFormatter {
            verbose: VerboseLevel::from_u8(verbose_level),
            term: Term::stdout(),
            last_event: None,
            repeat_count: 0,
            repeat_first_frame: 0,
            repeat_first_ts: Duration::ZERO,
            repeat_last_frame: 0,
            repeat_last_ts: Duration::ZERO,
            last_printed_lines: 0,
        }
    }

    // ─── Public API: called during capture ───

    /// Report errors detected in an EtherCAT frame. Called immediately during capture.
    /// If correlations are provided, ESM errors will show their related WKC error as a sub-line.
    pub fn report(&mut self, error: ECError, correlations: &[ErrorCorrelation]) {
        if self.verbose == VerboseLevel::Nothing {
            return;
        }

        match error {
            ECError::InvalidDatagram(e) => {
                self.emit_datagram_error(&e);
            }
            ECError::DeviceError(errors) => {
                for err in &errors {
                    self.emit_device_error(err, correlations);
                }
            }
        }
    }

    /// Report state transitions detected in an EtherCAT frame. Called immediately during capture.
    pub fn report_state_transitions(&mut self, transitions: &[StateTransition]) {
        if self.verbose == VerboseLevel::Nothing {
            return;
        }

        for tr in transitions {
            self.emit_state_transition(tr);
        }
    }

    /// Print a final summary line with frame count (called after capture ends).
    pub fn print_summary(&mut self, total_frames: u64) {
        if self.verbose == VerboseLevel::Nothing {
            return;
        }

        self.flush_repeat();

        println!();
        self.print_heavy_separator();
        println!("{}", style("  ■ capture complete").green().bold());
        println!(
            "{}",
            style(format!("    {} frames analyzed", total_frames)).color256(244)
        );
        self.print_heavy_separator();
    }

    // ─── Event emission ───

    fn emit_datagram_error(&mut self, error: &ECPacketError) {
        let detail = format!("{:?}", error);
        let key = format!("datagram:{}", detail);
        let msg = Self::format_tagged_line("DATAGRAM", &detail, None, None, Color::Red);
        self.emit_event(key, msg, 0, Duration::ZERO);
    }

    fn emit_device_error(&mut self, error: &ECDeviceError, correlations: &[ErrorCorrelation]) {
        let (key, msg, frame, ts, corr): (String, String, u64, Duration, Option<WkcErrorDetail>) =
            match error {
                ECDeviceError::InvalidAutoIncrementAddress {
                    packet_number,
                    timestamp,
                    command,
                    address,
                } => {
                    let key = format!("addr:auto_inc:{:#06x}:{}", address, command.as_str());
                    let detail = format!(
                        "{} auto-increment {:#06x} not found",
                        command.as_str(),
                        address
                    );
                    let msg = Self::format_tagged_line(
                        "ADDR",
                        &detail,
                        Some(*packet_number),
                        Some(*timestamp),
                        Color::Yellow,
                    );
                    (key, msg, *packet_number, *timestamp, None)
                }
                ECDeviceError::InvalidConfiguredAddress {
                    packet_number,
                    timestamp,
                    command,
                    address,
                } => {
                    let key = format!("addr:config:{:#06x}:{}", address, command.as_str());
                    let detail =
                        format!("{} configured {:#06x} not found", command.as_str(), address);
                    let msg = Self::format_tagged_line(
                        "ADDR",
                        &detail,
                        Some(*packet_number),
                        Some(*timestamp),
                        Color::Yellow,
                    );
                    (key, msg, *packet_number, *timestamp, None)
                }
                ECDeviceError::InvalidWkc(d) => {
                    let sub = d
                        .subdevice_id
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "—".to_string());
                    let cause = Self::wkc_cause_short(d.expected, d.actual);
                    let key = format!(
                        "wkc:{}:{}:{}:{}",
                        d.command.as_str(),
                        sub,
                        d.expected,
                        d.actual
                    );
                    let detail = format!(
                        "{} [{}] expected:{} actual:{} ({})",
                        d.command.as_str(),
                        sub,
                        d.expected,
                        d.actual,
                        cause,
                    );
                    let msg = Self::format_tagged_line(
                        "WKC",
                        &detail,
                        Some(d.packet_number),
                        Some(d.timestamp),
                        Color::Red,
                    );
                    (key, msg, d.packet_number, d.timestamp, None)
                }
                ECDeviceError::ESMError(d) => {
                    let esm_short = Self::esm_error_short(&d.error);
                    // Include the correlated WKC error in the dedup key so that
                    // the same ESM+WKC pair collapses together.
                    let corr = Self::find_correlation_for_esm(d, correlations);
                    let key = format!(
                        "esm:{}:{:?}",
                        d.subdevice_id,
                        std::mem::discriminant(&d.error)
                    );
                    let detail =
                        format!("[{}] {} {}", d.subdevice_id, d.command.as_str(), esm_short);
                    let msg = Self::format_tagged_line(
                        "ESM",
                        &detail,
                        Some(d.packet_number),
                        Some(d.timestamp),
                        Color::Magenta,
                    );
                    (key, msg, d.packet_number, d.timestamp, corr)
                }
            };

        self.emit_event(key, msg, frame, ts);

        // Print sub-lines only for the first occurrence (not during repeats)
        if self.repeat_count <= 1 {
            // Show correlated WKC error as a sub-line (same format as WKC error display)
            if let Some(ref c) = corr {
                let sub = c
                    .subdevice_id
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "—".to_string());
                let cause = Self::wkc_cause_short(c.expected, c.actual);
                let wkc_detail = format!(
                    "{} [{}] expected:{} actual:{} ({})",
                    c.command.as_str(),
                    sub,
                    c.expected,
                    c.actual,
                    cause,
                );
                let wkc_sub_line = Self::format_tagged_line(
                    "WKC",
                    &wkc_detail,
                    Some(c.packet_number),
                    Some(c.timestamp),
                    Color::Red,
                );
                println!("{} {}", style("         └─").color256(244), wkc_sub_line);
            }

            // In Detailed mode, also print the diagnosis on a separate line
            if self.verbose >= VerboseLevel::Detailed {
                let diagnosis = error.diagnosis();
                println!(
                    "{}",
                    style(format!("         └─ {}", diagnosis)).color256(244)
                );
            }
        }
    }

    fn emit_state_transition(&mut self, tr: &StateTransition) {
        let key = format!("transition:{}:{}:{}", tr.subdevice_id, tr.from, tr.to);

        let arrow = if tr.to > tr.from {
            style("->").green().to_string()
        } else {
            style("->").red().to_string()
        };

        let detail = format!("[{}] {} {} {}", tr.subdevice_id, tr.from, arrow, tr.to);
        let msg = Self::format_tagged_line(
            "STATE",
            &detail,
            Some(tr.packet_number),
            Some(tr.timestamp),
            Color::Cyan,
        );
        self.emit_event(key, msg, tr.packet_number, tr.timestamp);
    }

    /// Find a correlation that matches this ESM error (same subdevice, same ESM error).
    fn find_correlation_for_esm(
        esm: &crate::analyzer::ESMErrorDetail,
        correlations: &[ErrorCorrelation],
    ) -> Option<WkcErrorDetail> {
        correlations
            .iter()
            .find(|c| {
                c.esm_error.subdevice_id == esm.subdevice_id
                    && c.esm_error.packet_number == esm.packet_number
            })
            .map(|c| c.wkc_error)
    }

    // ─── Core logic ───

    /// Emit a single event. If the same event key was just displayed, overwrite
    /// the last line with an updated repeat count instead of printing a new line.
    fn emit_event(&mut self, key: String, base_message: String, frame: u64, ts: Duration) {
        let sig = EventSignature {
            key,
            base_message: base_message.clone(),
        };

        if let Some(ref last) = self.last_event {
            if last.key == sig.key {
                // Same event repeating — increment count and overwrite last line
                self.repeat_count += 1;
                self.repeat_last_frame = frame;
                self.repeat_last_ts = ts;
                self.overwrite_repeat_line();
                return;
            }
        }

        // Different event — start a new line
        // (The previous repeat line, if any, is already finalized on stdout)
        self.last_event = Some(sig);
        self.repeat_count = 1;
        self.repeat_first_frame = frame;
        self.repeat_first_ts = ts;
        self.repeat_last_frame = frame;
        self.repeat_last_ts = ts;
        self.last_printed_lines = 0;

        let lines = self.count_terminal_lines(&base_message);
        println!("{}", base_message);
        self.last_printed_lines = lines;
    }

    /// Calculate how many terminal lines a string occupies when printed,
    /// accounting for line wrapping at the terminal width boundary.
    fn count_terminal_lines(&self, text: &str) -> usize {
        let term_width = self.terminal_width();
        let visible_width = measure_text_width(text);
        if visible_width == 0 || term_width == 0 {
            return 1;
        }
        // Ceiling division: how many rows the text spans
        (visible_width + term_width - 1) / term_width
    }

    /// Get the current terminal width, with a safe fallback.
    fn terminal_width(&self) -> usize {
        let (_rows, cols) = self.term.size();
        cols as usize
    }

    /// Overwrite the last line on stdout with a summary showing the repeat count.
    fn overwrite_repeat_line(&mut self) {
        let base = match self.last_event {
            Some(ref e) => e.base_message.clone(),
            None => return,
        };

        // Build the repeat summary line
        let repeat_suffix = format!(
            " (×{}, #{}-#{}, {:.3}s-{:.3}s)",
            self.repeat_count,
            self.repeat_first_frame,
            self.repeat_last_frame,
            self.repeat_first_ts.as_secs_f64(),
            self.repeat_last_ts.as_secs_f64(),
        );

        let full_line = format!("{}{}", base, style(&repeat_suffix).color256(244));

        // Calculate how many terminal lines the *previous* output occupied
        let lines_to_clear = if self.repeat_count == 2 {
            0
        } else {
            self.last_printed_lines
        };

        // Clear the previous output (handles wrapped lines correctly)
        if lines_to_clear > 0 {
            let _ = self.term.clear_last_lines(lines_to_clear);
        }

        // Calculate how many lines the new output will occupy
        let new_lines = self.count_terminal_lines(&full_line);

        println!("{}", full_line);
        let _ = self.term.flush();
        self.last_printed_lines = new_lines;
    }

    /// Flush any pending repeat state. Called before printing non-event output.
    fn flush_repeat(&mut self) {
        self.last_event = None;
        self.repeat_count = 0;
        self.last_printed_lines = 0;
    }

    // ─── Formatting helpers ───

    /// Format a tagged error line in the pop style:
    ///   ▌ TAG  #frame [timestamp] detail
    fn format_tagged_line(
        tag: &str,
        detail: &str,
        frame: Option<u64>,
        timestamp: Option<Duration>,
        tag_color: Color,
    ) -> String {
        let tag_style = Style::new().fg(tag_color).bold();
        let dim_style = Style::new().color256(244); // dark grey

        let mut out = String::new();

        // "  ▌ "
        out.push_str(&format!("  {} ", tag_style.apply_to("▌")));

        // "TAG     " (left-padded to 8 chars)
        out.push_str(&format!("{}", tag_style.apply_to(format!("{:<8}", tag))));

        // "#frame  [timestamp] " (dim)
        if let (Some(f), Some(ts)) = (frame, timestamp) {
            out.push_str(&format!(
                "{} ",
                dim_style.apply_to(format!("#{:<6} [{:>9.6}s]", f, ts.as_secs_f64()))
            ));
        }

        // detail text (unstyled)
        out.push_str(detail);

        out
    }

    // ─── Visual helpers ───

    /// Format an interface info line in the same tagged-line style as errors.
    pub fn format_interface_line(
        name: &str,
        description: &str,
        oper_state: &str,
        is_default: bool,
    ) -> String {
        let suffix = if is_default { ", default" } else { "" };
        let detail = format!("{} [{}{}]", description, oper_state, suffix);
        // Build a tagged line with "IF" as placeholder, then replace with the name
        Self::format_tagged_line("IF", &detail, None, None, Color::Green)
            .replace("IF      ", &format!("{:<8}", name))
    }

    fn print_heavy_separator(&self) {
        println!("{}", style(format!("  {}", "━".repeat(76))).color256(244));
    }

    // ─── Data helpers ───

    fn wkc_cause_short(expected: u16, actual: u16) -> &'static str {
        if actual == 0 {
            "no response"
        } else if actual < expected {
            "partial"
        } else {
            "over-count"
        }
    }

    fn esm_error_short(error: &ecdump::subdevice::ESMError) -> String {
        use ecdump::subdevice::ESMError;
        match error {
            ESMError::IllegalTransition { to } => {
                format!("illegal -> {}", to)
            }
            ESMError::InvalidStateTransition { requested, current } => {
                format!("{} -> {} invalid", current, requested)
            }
            ESMError::BackwardTransition {
                from,
                to,
                has_error,
            } => {
                let flag = if *has_error { " +err" } else { "" };
                format!("{} -> {} backward{}", from, to, flag)
            }
            ESMError::TransitionFailed {
                requested,
                current,
                has_error,
            } => {
                let flag = if *has_error { " +err" } else { "" };
                format!(" -> {} failed @{}{}", requested, current, flag)
            }
        }
    }
}

impl Drop for ErrorFormatter {
    fn drop(&mut self) {
        self.flush_repeat();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verbose_level_ordering() {
        assert!(VerboseLevel::Nothing < VerboseLevel::Normal);
        assert!(VerboseLevel::Normal < VerboseLevel::Detailed);
        assert!(VerboseLevel::Detailed < VerboseLevel::Debug);
    }

    #[test]
    fn test_wkc_cause_short() {
        assert_eq!(ErrorFormatter::wkc_cause_short(3, 0), "no response");
        assert_eq!(ErrorFormatter::wkc_cause_short(3, 2), "partial");
        assert_eq!(ErrorFormatter::wkc_cause_short(1, 3), "over-count");
    }

    #[test]
    fn test_esm_error_short() {
        use ecdump::subdevice::{ECState, ESMError};

        let err = ESMError::BackwardTransition {
            from: ECState::Op,
            to: ECState::SafeOp,
            has_error: true,
        };
        let s = ErrorFormatter::esm_error_short(&err);
        assert!(s.contains("backward"), "got: {}", s);
        assert!(s.contains("+err"), "got: {}", s);

        let err2 = ESMError::TransitionFailed {
            requested: ECState::Op,
            current: ECState::SafeOp,
            has_error: false,
        };
        let s2 = ErrorFormatter::esm_error_short(&err2);
        assert!(s2.contains("failed"), "got: {}", s2);
        assert!(!s2.contains("+err"), "got: {}", s2);
    }

    #[test]
    fn test_format_tagged_line_with_frame() {
        let line = ErrorFormatter::format_tagged_line(
            "WKC",
            "some detail",
            Some(42),
            Some(Duration::from_secs_f64(1.234)),
            Color::Red,
        );
        assert!(line.contains("WKC"), "got: {}", line);
        assert!(line.contains("some detail"), "got: {}", line);
        assert!(line.contains("42"), "got: {}", line);
    }

    #[test]
    fn test_format_tagged_line_without_frame() {
        let line =
            ErrorFormatter::format_tagged_line("DATAGRAM", "bad packet", None, None, Color::Red);
        assert!(line.contains("DATAGRAM"), "got: {}", line);
        assert!(line.contains("bad packet"), "got: {}", line);
    }

    #[test]
    fn test_find_correlation_for_esm() {
        use crate::analyzer::{ESMErrorDetail, WkcErrorDetail};
        use ecdump::ec_packet::ECCommands;
        use ecdump::subdevice::{ECState, ESMError, SubdeviceIdentifier};

        let wkc = WkcErrorDetail {
            packet_number: 10,
            command: ECCommands::FPWR,
            from_main: true,
            timestamp: Duration::from_secs(1),
            expected: 1,
            actual: 0,
            subdevice_id: Some(SubdeviceIdentifier::Address(0x1001)),
        };

        let esm = ESMErrorDetail {
            packet_number: 12,
            timestamp: Duration::from_secs(2),
            command: ECCommands::FPRD,
            subdevice_id: SubdeviceIdentifier::Address(0x1001),
            error: ESMError::BackwardTransition {
                from: ECState::Op,
                to: ECState::SafeOp,
                has_error: true,
            },
        };

        let corr = ErrorCorrelation {
            wkc_error: wkc,
            esm_error: esm,
            frame_gap: 2,
        };

        // Should find the correlation when packet_number matches
        let found = ErrorFormatter::find_correlation_for_esm(&esm, &[corr.clone()]);
        assert!(found.is_some());
        assert_eq!(found.unwrap().packet_number, 10);

        // Should not find if packet_number differs
        let mut esm2 = esm;
        esm2.packet_number = 99;
        let not_found = ErrorFormatter::find_correlation_for_esm(&esm2, &[corr]);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_count_terminal_lines() {
        let formatter = ErrorFormatter::new(1);
        // A short string should be 1 line
        assert_eq!(formatter.count_terminal_lines("hello"), 1);
        // Empty string should be 1 line
        assert_eq!(formatter.count_terminal_lines(""), 1);
    }
}
