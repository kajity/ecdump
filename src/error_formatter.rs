use console::{Color, Style, Term, measure_text_width, style};
use std::time::Duration;

use crate::analyzer::{
    AlStatusCodeUpdate, ECDeviceError, ECError, ErrorCorrelation, StateTransition, WkcErrorDetail,
};
use ecdump::ec_packet::ECPacketError;
use ecdump::registers::format_al_status_code;
use ecdump::subdevice::SubdeviceIdentifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerboseLevel {
    Nothing = 0,
    Normal = 1,
    Detailed = 2,
}

impl VerboseLevel {
    pub fn from_u8(level: u8) -> Self {
        match level {
            0 => VerboseLevel::Nothing,
            1 => VerboseLevel::Normal,
            _ => VerboseLevel::Detailed,
        }
    }
}

// ─── Rendered Output ───

#[derive(Debug, Clone)]
struct RenderedLine {
    text: String,
    line_count: usize,
}

impl RenderedLine {
    fn new(text: String, term_width: usize) -> Self {
        let line_count = count_lines_with_wrapping(&text, term_width);
        Self { text, line_count }
    }

    fn write_to(&self, term: &Term) {
        let _ = term.write_line(&self.text);
    }

    fn rewrite_in_place(&self, previous_line_count: usize, term: &Term, lines_below: usize) {
        let total_up = lines_below + previous_line_count;
        if total_up > 0 {
            let _ = term.move_cursor_up(total_up);
        }
        let clear_count = previous_line_count.max(self.line_count);
        for i in 0..clear_count {
            let _ = term.clear_line();
            if i + 1 < clear_count {
                let _ = term.move_cursor_down(1);
            }
        }
        if clear_count > 1 {
            let _ = term.move_cursor_up(clear_count - 1);
        }

        self.write_to(term);
        if lines_below > 0 {
            let _ = term.move_cursor_down(lines_below);
        }
    }
}

#[derive(Debug, Clone)]
struct RenderedBlock {
    event: RenderedLine,
    details: Vec<RenderedLine>,
}

impl RenderedBlock {
    fn write_to(&self, term: &Term) {
        self.event.write_to(term);
        for detail in &self.details {
            detail.write_to(term);
        }
    }

    fn detail_lines_total(&self) -> usize {
        self.details.iter().map(|detail| detail.line_count).sum()
    }

    fn detail_lines_below(&self, idx: usize) -> usize {
        self.details
            .iter()
            .skip(idx + 1)
            .map(|detail| detail.line_count)
            .sum()
    }
}

/// An event line component (tagged line with frame/timestamp info).
#[derive(Debug, Clone)]
struct EventLine {
    tag: String,
    tag_color: Color,
    detail: String,
    frame: Option<u64>,
    timestamp: Option<Duration>,
}

impl EventLine {
    fn new(
        tag: &str,
        detail: &str,
        frame: Option<u64>,
        timestamp: Option<Duration>,
        tag_color: Color,
    ) -> Self {
        EventLine {
            tag: tag.to_string(),
            tag_color,
            detail: detail.to_string(),
            frame,
            timestamp,
        }
    }

    fn render(&self, term_width: usize) -> RenderedLine {
        RenderedLine::new(self.render_without_repeat(), term_width)
    }

    fn render_repeated(
        &self,
        term_width: usize,
        repeat_count: usize,
        first_frame: u64,
        last_frame: u64,
        first_ts: Duration,
        last_ts: Duration,
    ) -> RenderedLine {
        let mut base = self.render_without_repeat();
        let repeat_suffix = format!(
            " (×{}, #{}-#{}, {:.3}s-{:.3}s)",
            repeat_count,
            first_frame,
            last_frame,
            first_ts.as_secs_f64(),
            last_ts.as_secs_f64()
        );
        base.push_str(&style(&repeat_suffix).color256(244).to_string());
        RenderedLine::new(base, term_width)
    }

    /// Render without any repeat summary.
    fn render_without_repeat(&self) -> String {
        let tag_style = Style::new().fg(self.tag_color).bold();
        let dim_style = Style::new().color256(244);

        let mut out = String::new();
        out.push_str(&format!("  {} ", tag_style.apply_to("▌")));
        out.push_str(&format!(
            "{}",
            tag_style.apply_to(format!("{:<8}", self.tag))
        ));
        out.push(' ');

        match (self.frame, self.timestamp) {
            (Some(f), Some(ts)) => {
                out.push_str(&format!(
                    "{} ",
                    dim_style.apply_to(format!("#{:<6} [{:>9.6}s]", f, ts.as_secs_f64()))
                ));
            }
            (Some(f), None) => {
                out.push_str(&format!("{} ", dim_style.apply_to(format!("#{:<6}", f))));
            }
            (None, Some(ts)) => {
                out.push_str(&format!(
                    "{} ",
                    dim_style.apply_to(format!("[{:>9.6}s]", ts.as_secs_f64()))
                ));
            }
            (None, None) => {}
        }

        out.push_str(&self.detail);
        out
    }
}

/// A detail line component (child of an event, with tree branch).
#[derive(Debug, Clone)]
struct DetailLine {
    content: String,
    dimmed: bool,
}

impl DetailLine {
    fn new(content: String, dimmed: bool) -> Self {
        DetailLine { content, dimmed }
    }

    fn update_content(&mut self, new_content: String) {
        self.content = new_content;
    }

    fn render_with_branch(&self, is_last: bool, is_only: bool, term_width: usize) -> RenderedLine {
        let branch = if is_only || is_last {
            "└─"
        } else {
            "├─"
        };
        let prefix = style(format!("         {}", branch))
            .color256(244)
            .to_string();
        let content = if self.dimmed {
            style(&self.content).color256(244).to_string()
        } else {
            self.content.clone()
        };
        RenderedLine::new(format!("{} {}", prefix, content), term_width)
    }
}

/// An output block: event line + optional detail lines (tree structure).
#[derive(Debug, Clone)]
struct OutputBlock {
    key: String,
    event: EventLine,
    details: Vec<DetailLine>,
}

impl OutputBlock {
    fn new(key: String, event: EventLine) -> Self {
        OutputBlock {
            key,
            event,
            details: Vec::new(),
        }
    }

    fn add_detail(&mut self, detail: DetailLine) {
        self.details.push(detail);
    }

    fn render(&self, term_width: usize) -> RenderedBlock {
        let mut details = Vec::with_capacity(self.details.len());

        let detail_count = self.details.len();
        for (idx, detail) in self.details.iter().enumerate() {
            let is_last = idx + 1 == detail_count;
            let is_only = detail_count == 1;
            details.push(detail.render_with_branch(is_last, is_only, term_width));
        }

        RenderedBlock {
            event: self.event.render(term_width),
            details,
        }
    }
}

/// Calculate how many terminal lines a string occupies with wrapping.
fn count_lines_with_wrapping(text: &str, term_width: usize) -> usize {
    if term_width == 0 {
        return 1;
    }

    text.split('\n')
        .map(|line| {
            let visible_width = measure_text_width(line);
            if visible_width == 0 {
                1
            } else {
                (visible_width + term_width - 1) / term_width
            }
        })
        .sum()
}

pub struct ErrorFormatter {
    verbose: VerboseLevel,
    term: Term,
    /// The last displayed output block (event + detail lines).
    last_block: Option<OutputBlock>,
    /// Cached rendered form of the last displayed block.
    last_rendered_block: Option<RenderedBlock>,
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
    /// repeat_count value at which we last performed an overwrite (for throttling).
    last_overwrite_at: usize,
    /// Minimum number of new repeats required before we perform an overwrite.
    overwrite_interval: usize,
    /// Whether the last emitted event was an ESM error (any type).
    last_esm_error: bool,
    /// The subdevice identifier for the last ESM error.
    last_esm_subdevice: Option<SubdeviceIdentifier>,
    /// The AL Status Code currently displayed for the last ESM error (if any).
    last_esm_al_status_code: Option<u16>,
    /// Index of the AL Status Code detail line in the last block.
    last_al_status_detail_index: Option<usize>,
}

impl ErrorFormatter {
    pub fn new(verbose_level: u8) -> Self {
        ErrorFormatter {
            verbose: VerboseLevel::from_u8(verbose_level),
            term: Term::stdout(),
            last_block: None,
            last_rendered_block: None,
            repeat_count: 0,
            repeat_first_frame: 0,
            repeat_first_ts: Duration::ZERO,
            repeat_last_frame: 0,
            repeat_last_ts: Duration::ZERO,
            last_overwrite_at: 0,
            overwrite_interval: 10,
            last_esm_error: false,
            last_esm_subdevice: None,
            last_esm_al_status_code: None,
            last_al_status_detail_index: None,
        }
    }

    // ─── Public API: called during capture ───

    /// Report AL Status Code updates for devices with pending ESM errors.
    /// If the last displayed event was an ESM error for the given subdevice,
    /// the output will be rewritten to include the updated AL Status Code.
    pub fn report_al_status_code_updates(&mut self, updates: &[AlStatusCodeUpdate]) {
        if self.verbose == VerboseLevel::Nothing || !self.last_esm_error {
            return;
        }

        for update in updates {
            if self.last_esm_subdevice.as_ref() == Some(&update.subdevice_id) {
                let already_shown = self.last_esm_al_status_code;
                if already_shown == Some(update.al_status_code) {
                    continue; // No change
                }
                self.rewrite_al_status_code_detail(update.al_status_code);
            }
        }
    }

    /// Report errors detected in an EtherCAT frame. Called immediately during capture.
    /// If correlations are provided, ESM errors will show their related WKC error as a sub-line.
    pub fn report(&mut self, error: ECError, correlations: &[ErrorCorrelation]) {
        if self.verbose == VerboseLevel::Nothing {
            return;
        }

        match error {
            ECError::InvalidDatagram {
                packet_number,
                timestamp,
                error: e,
            } => {
                self.emit_datagram_error(packet_number, timestamp, &e);
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

    fn emit_datagram_error(
        &mut self,
        packet_number: u64,
        timestamp: Duration,
        error: &ECPacketError,
    ) {
        let detail = error.to_string();
        let key = format!("datagram:{}", detail);
        let event = EventLine::new(
            "FRAME",
            &detail,
            Some(packet_number),
            Some(timestamp),
            Color::Red,
        );
        self.emit_output_block(OutputBlock::new(key, event));
    }

    fn emit_device_error(&mut self, error: &ECDeviceError, correlations: &[ErrorCorrelation]) {
        // A new device error is being emitted — clear ESM tracking
        // (it will be re-set below if this error is itself an ESM error)
        self.clear_esm_tracking();

        let (key, event, corr, esm_info): (
            String,
            EventLine,
            Option<WkcErrorDetail>,
            Option<(SubdeviceIdentifier, Option<u16>)>,
        ) = match error {
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
                let event = EventLine::new(
                    "ADDR",
                    &detail,
                    Some(*packet_number),
                    Some(*timestamp),
                    Color::Yellow,
                );
                (key, event, None, None)
            }
            ECDeviceError::InvalidConfiguredAddress {
                packet_number,
                timestamp,
                command,
                address,
            } => {
                let key = format!("addr:config:{:#06x}:{}", address, command.as_str());
                let detail = format!("{} configured {:#06x} not found", command.as_str(), address);
                let event = EventLine::new(
                    "ADDR",
                    &detail,
                    Some(*packet_number),
                    Some(*timestamp),
                    Color::Yellow,
                );
                (key, event, None, None)
            }
            ECDeviceError::InvalidWkc(d) => {
                let sub = d
                    .subdevice_id
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "—".to_string());
                let cause = Self::wkc_cause_short(d.expected, d.actual);
                let key = format!(
                    "wkc:{}:{}:{}:{}:{}",
                    d.command.as_str(),
                    d.register,
                    sub,
                    d.expected,
                    d.actual
                );
                let reg_str = if d.length == 1 {
                    format!("{:#06x}", d.register)
                } else {
                    format!("{:#06x}..{:04x}", d.register, d.register + d.length - 1)
                };
                let detail = format!(
                    "[{}] {} {}; expected:{} actual:{} ({})",
                    sub,
                    d.command.as_str(),
                    reg_str,
                    d.expected,
                    d.actual,
                    cause,
                );
                let event = EventLine::new(
                    "WKC",
                    &detail,
                    Some(d.packet_number),
                    Some(d.timestamp),
                    Color::Red,
                );
                (key, event, None, None)
            }
            ECDeviceError::ESMError(d) => {
                let esm_short = Self::esm_error_short(&d.error);
                let corr = Self::find_correlation_for_esm(d, correlations);
                let key = format!(
                    "esm:{}:{:?}",
                    d.subdevice_id,
                    std::mem::discriminant(&d.error)
                );
                let detail = format!("[{}] {}; {}", d.subdevice_id, d.command.as_str(), esm_short);
                let event = EventLine::new(
                    "ESM",
                    &detail,
                    Some(d.packet_number),
                    Some(d.timestamp),
                    Color::Magenta,
                );
                let esm_info = Some((d.subdevice_id, d.al_status_code));

                (key, event, corr, esm_info)
            }
        };
        self.emit_output_block_with_details(OutputBlock::new(key, event), corr, esm_info, error);
    }

    fn emit_state_transition(&mut self, tr: &StateTransition) {
        let key = format!("transition:{}:{}:{}", tr.subdevice_id, tr.from, tr.to);

        let arrow = if tr.to > tr.from {
            style("->").green().to_string()
        } else {
            style("->").red().to_string()
        };

        let detail = format!("[{}] {} {} {}", tr.subdevice_id, tr.from, arrow, tr.to);
        let event = EventLine::new(
            "STATE",
            &detail,
            Some(tr.packet_number),
            Some(tr.timestamp),
            Color::Cyan,
        );
        self.emit_output_block(OutputBlock::new(key, event));
    }

    // ─── Core component logic ───

    fn emit_output_block(&mut self, block: OutputBlock) {
        self.emit_output_block_internal(block);
    }

    fn emit_output_block_with_details(
        &mut self,
        mut block: OutputBlock,
        corr: Option<WkcErrorDetail>,
        esm_info: Option<(SubdeviceIdentifier, Option<u16>)>,
        error: &ECDeviceError,
    ) {
        if !self.is_same_event(&block) {
            if let Some(ref c) = corr {
                let sub = c
                    .subdevice_id
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "—".to_string());
                let cause = Self::wkc_cause_short(c.expected, c.actual);
                let wkc_detail = format!(
                    "[{}] {}; expected:{} actual:{} ({})",
                    sub,
                    c.command.as_str(),
                    c.expected,
                    c.actual,
                    cause,
                );
                let wkc_line = EventLine::new(
                    "WKC",
                    &wkc_detail,
                    Some(c.packet_number),
                    Some(c.timestamp),
                    Color::Red,
                );
                block.add_detail(DetailLine::new(wkc_line.render_without_repeat(), false));
            }

            if self.verbose >= VerboseLevel::Detailed {
                block.add_detail(DetailLine::new(error.diagnosis(), true));
            }

            if self.verbose >= VerboseLevel::Detailed {
                if let Some((subdevice_id, al_code)) = esm_info {
                    self.last_esm_error = true;
                    self.last_esm_subdevice = Some(subdevice_id);
                    self.last_esm_al_status_code = al_code;
                    self.last_al_status_detail_index = Some(block.details.len());

                    let al_text = match al_code {
                        Some(code) => format!("AL Status Code: {}", format_al_status_code(code)),
                        None => "AL Status Code: (pending)".to_string(),
                    };
                    block.add_detail(DetailLine::new(al_text, true));
                }
            }
        }

        self.emit_output_block_internal(block);
    }

    fn emit_output_block_internal(&mut self, block: OutputBlock) {
        let term_width = self.terminal_width();
        if self.is_same_event(&block) {
            self.repeat_count += 1;
            self.repeat_last_frame = block.event.frame.unwrap_or(0);
            self.repeat_last_ts = block.event.timestamp.unwrap_or(Duration::ZERO);

            let due = self.repeat_count - self.last_overwrite_at >= self.overwrite_interval;
            if due {
                self.overwrite_repeat_block();
                self.last_overwrite_at = self.repeat_count;
            }
            return;
        }

        self.repeat_count = 1;
        self.last_overwrite_at = 0;
        self.repeat_first_frame = block.event.frame.unwrap_or(0);
        self.repeat_first_ts = block.event.timestamp.unwrap_or(Duration::ZERO);
        self.repeat_last_frame = self.repeat_first_frame;
        self.repeat_last_ts = self.repeat_first_ts;

        let rendered = block.render(term_width);
        rendered.write_to(&self.term);
        self.last_block = Some(block);
        self.last_rendered_block = Some(rendered);
    }

    fn overwrite_repeat_block(&mut self) -> Option<()> {
        let term_width = self.terminal_width();
        let block = self.last_block.as_ref()?;
        let rendered_block = self.last_rendered_block.as_mut()?;

        let rendered_event = block.event.render_repeated(
            term_width,
            self.repeat_count,
            self.repeat_first_frame,
            self.repeat_last_frame,
            self.repeat_first_ts,
            self.repeat_last_ts,
        );

        let old_event_line_count = rendered_block.event.line_count;
        let detail_lines_total = rendered_block.detail_lines_total();

        if old_event_line_count == rendered_event.line_count {
            // If the event line didn't change height, we can just rewrite it in place
            rendered_event.rewrite_in_place(old_event_line_count, &self.term, detail_lines_total);
            rendered_block.event = rendered_event;
        } else {
            // Otherwise, we need to rewrite the entire block to avoid messing up the detail lines
            let _ = self
                .term
                .move_cursor_up(old_event_line_count + detail_lines_total);
            rendered_block.event = rendered_event;
            rendered_block.write_to(&self.term);
        }

        let _ = self.term.flush();
        Some(())
    }

    fn rewrite_al_status_code_detail(&mut self, code: u16) {
        if !self.last_esm_error {
            return;
        }

        let Some(idx) = self.last_al_status_detail_index else {
            return;
        };
        let term_width = self.terminal_width();
        let Some(block) = self.last_block.as_mut() else {
            return;
        };
        let Some(rendered_block) = self.last_rendered_block.as_mut() else {
            return;
        };
        if idx >= block.details.len() || idx >= rendered_block.details.len() {
            return;
        }

        let al_text = format!("AL Status Code: {}", format_al_status_code(code));
        let detail_count = block.details.len();
        let is_last = idx + 1 == detail_count;
        let is_only = detail_count == 1;

        block.details[idx].update_content(al_text);
        let rendered_detail = block.details[idx].render_with_branch(is_last, is_only, term_width);
        let lines_below = rendered_block.detail_lines_below(idx);
        let previous_line_count = rendered_block.details[idx].line_count;
        rendered_detail.rewrite_in_place(previous_line_count, &self.term, lines_below);
        rendered_block.details[idx] = rendered_detail;

        let _ = self.term.flush();
        self.last_esm_al_status_code = Some(code);
    }

    /// Get the current terminal width, with a safe fallback.
    fn terminal_width(&self) -> usize {
        let (_rows, cols) = self.term.size();
        cols as usize
    }

    /// Flush any pending repeat state. Called before printing non-event output.
    fn flush_repeat(&mut self) {
        if self.repeat_count > 1 && self.repeat_count != self.last_overwrite_at {
            self.overwrite_repeat_block();
        }
        self.last_block = None;
        self.last_rendered_block = None;
        self.repeat_count = 0;
        self.last_overwrite_at = 0;
        self.clear_esm_tracking();
    }

    /// Clear ESM error tracking state.
    fn clear_esm_tracking(&mut self) {
        self.last_esm_error = false;
        self.last_esm_subdevice = None;
        self.last_esm_al_status_code = None;
        self.last_al_status_detail_index = None;
    }

    // ─── Formatting helpers ───

    /// Format an interface info line in the same tagged-line style as errors.
    pub fn format_interface_line(
        name: &str,
        description: &str,
        oper_state: &str,
        is_default: bool,
    ) -> String {
        let suffix = if is_default { ", default" } else { "" };
        let detail = format!("{} [{}{}]", description, oper_state, suffix);
        let event = EventLine::new(name, &detail, None, None, Color::Green);
        event.render_without_repeat()
    }

    fn print_heavy_separator(&self) {
        println!("{}", style(format!("  {}", "━".repeat(76))).color256(244));
    }

    // ─── Data helpers ───
    fn is_same_event(&self, block: &OutputBlock) -> bool {
        self.last_block
            .as_ref()
            .map_or(false, |lb| lb.key == block.key)
    }

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
                format!("-> {} failed @{}{}", requested, current, flag)
            }
        }
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
    fn test_find_correlation_for_esm() {
        use crate::analyzer::{ESMErrorDetail, WkcErrorDetail};
        use ecdump::ec_packet::ECCommands;
        use ecdump::subdevice::{ECState, ESMError, SubdeviceIdentifier};

        let wkc = WkcErrorDetail {
            packet_number: 10,
            command: ECCommands::FPWR,
            register: 0x1234,
            length: 2,
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
            al_status_code: None,
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
    fn test_event_line_render_without_repeat_with_partial_metadata() {
        let frame_only = EventLine::new("TEST", "detail", Some(42), None, Color::Blue);
        let frame_only_rendered = frame_only.render_without_repeat();
        assert!(
            frame_only_rendered.contains("#42"),
            "got: {}",
            frame_only_rendered
        );

        let ts_only = EventLine::new(
            "TEST",
            "detail",
            None,
            Some(Duration::from_millis(1250)),
            Color::Blue,
        );
        let ts_only_rendered = ts_only.render_without_repeat();
        assert!(
            ts_only_rendered.contains("1.250000s"),
            "got: {}",
            ts_only_rendered
        );
    }
}
