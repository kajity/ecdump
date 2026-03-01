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

// ─── Line Component System ───

/// Trait for renderable line components.
/// Each component manages its own content and rendering logic.
#[allow(dead_code)]
trait LineComponent {
    /// Render the line with awareness of terminal width.
    /// Returns the formatted string to be printed.
    fn render(&self, term_width: usize) -> String;

    /// Calculate how many terminal lines this component occupies.
    fn line_count(&self, term_width: usize) -> usize;

    /// Get a unique identifier for this component (used for deduplication).
    fn signature_key(&self) -> String;

    /// Erase this component from the terminal.
    ///
    /// `lines_below` is the number of terminal lines that have been printed
    /// *below* this component (i.e. detail lines sitting beneath an event line).
    /// After the call the cursor is back at the original bottom position, but the
    /// lines formerly occupied by this component are blank.
    fn erase(&self, term: &Term, lines_below: usize, term_width: usize) {
        let count = self.line_count(term_width);
        let total_up = lines_below + count;
        if total_up > 0 {
            let _ = term.move_cursor_up(total_up);
        }
        // Clear each line that belongs to this component.
        for i in 0..count {
            let _ = term.clear_line();
            if i + 1 < count {
                let _ = term.move_cursor_down(1);
            }
        }
        // Cursor is now at the first line of this component (cleared).
        // Restore cursor to the original bottom position.
        if lines_below + count > 1 {
            let _ = term.move_cursor_down(lines_below + count - 1);
        } else if count == 1 && lines_below == 0 {
            // nothing to restore; cursor is already on the (blank) line we just cleared
        }
    }

    /// Rewrite this component in-place with `new_rendered` text.
    ///
    /// Returns the new line count so the caller can update its tracking state.
    /// The cursor is left at the original bottom position when this returns.
    fn rewrite_in_place(
        &self,
        new_rendered: &str,
        term: &Term,
        lines_below: usize,
        term_width: usize,
    ) -> usize {
        let old_count = self.line_count(term_width);
        let new_count = count_lines_with_wrapping(new_rendered, term_width);
        let total_up = lines_below + old_count;

        // Move cursor to the first line of this component.
        if total_up > 0 {
            let _ = term.move_cursor_up(total_up);
        }

        // Clear the lines that the old rendering occupied
        // (use whichever is larger so we never leave stale content).
        let clear_count = old_count.max(new_count);
        for i in 0..clear_count {
            let _ = term.clear_line();
            if i + 1 < clear_count {
                let _ = term.move_cursor_down(1);
            }
        }
        // Return cursor to the start of this component's region.
        if clear_count > 1 {
            let _ = term.move_cursor_up(clear_count - 1);
        }

        // Print the new content without a trailing newline so we control movement.
        print!("{}", new_rendered);

        // Advance past any remaining lines in the component region and past the
        // lines_below section to restore the cursor to the original bottom.
        // `print!` leaves the cursor at the end of the last printed character;
        // `println!` would put us on the next line.  We emit a newline here to
        // land on the line just after the new content.
        if lines_below > 0 {
            println!();
            if lines_below > 1 {
                let _ = term.move_cursor_down(lines_below - 1);
            }
        }

        new_count
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
    #[allow(dead_code)]
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

    /// Update the detail content of this event line.
    #[allow(dead_code)]
    fn update_detail(&mut self, new_detail: String) {
        self.detail = new_detail;
    }

    /// Add a repeat summary to the event line.
    fn with_repeat_summary(
        &self,
        repeat_count: usize,
        first_frame: u64,
        last_frame: u64,
        first_ts: Duration,
        last_ts: Duration,
    ) -> String {
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
        base
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

        if let (Some(f), Some(ts)) = (self.frame, self.timestamp) {
            out.push_str(&format!(
                "{} ",
                dim_style.apply_to(format!("#{:<6} [{:>9.6}s]", f, ts.as_secs_f64()))
            ));
        }

        out.push_str(&self.detail);
        out
    }
}

impl LineComponent for EventLine {
    fn render(&self, _term_width: usize) -> String {
        self.render_without_repeat()
    }

    #[allow(dead_code)]
    fn line_count(&self, term_width: usize) -> usize {
        let text = self.render_without_repeat();
        count_lines_with_wrapping(&text, term_width)
    }

    fn signature_key(&self) -> String {
        format!("event:{}:{}", self.tag, self.detail)
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

    /// Update the content of this detail line.
    #[allow(dead_code)]
    fn update_content(&mut self, new_content: String) {
        self.content = new_content;
    }

    /// Render this detail line with the appropriate tree branch.
    fn render_with_branch(&self, is_last: bool, is_only: bool, term_width: usize) -> String {
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
        let line = format!("{} {}", prefix, content);

        // If line wraps, we need to account for the prefix width in wrapping calculations
        let prefix_width = measure_text_width(&format!("         {}", branch));
        let content_width = measure_text_width(&self.content);
        let total_width = prefix_width + 1 + content_width;

        if term_width > 0 && total_width > term_width {
            // Line will wrap; keep the formatting intact
            line
        } else {
            line
        }
    }
}

impl LineComponent for DetailLine {
    fn render(&self, term_width: usize) -> String {
        // Default rendering (used when we don't know the branch position yet)
        self.render_with_branch(true, true, term_width)
    }

    #[allow(dead_code)]
    fn line_count(&self, term_width: usize) -> usize {
        let rendered = self.render(term_width);
        count_lines_with_wrapping(&rendered, term_width)
    }

    fn signature_key(&self) -> String {
        format!("detail:{}", self.content)
    }
}

/// An output block: event line + optional detail lines (tree structure).
#[derive(Debug, Clone)]
struct OutputBlock {
    event: EventLine,
    details: Vec<DetailLine>,
}

impl OutputBlock {
    #[allow(dead_code)]
    fn new(event: EventLine) -> Self {
        OutputBlock {
            event,
            details: Vec::new(),
        }
    }

    /// Add a detail line as a child.
    #[allow(dead_code)]
    fn add_detail(&mut self, detail: DetailLine) {
        self.details.push(detail);
    }

    /// Update an existing detail line or add if not found.
    #[allow(dead_code)]
    fn update_or_add_detail(&mut self, index: usize, new_detail: DetailLine) {
        if index < self.details.len() {
            self.details[index] = new_detail;
        } else {
            self.details.push(new_detail);
        }
    }

    /// Calculate total lines for this block (event + all details).
    #[allow(dead_code)]
    fn total_lines(&self, term_width: usize) -> usize {
        let event_lines = self.event.line_count(term_width);
        let detail_lines: usize = self.details.iter().map(|d| d.line_count(term_width)).sum();
        event_lines + detail_lines
    }

    /// Render the entire block (event + details as children).
    fn render_block(&self, term_width: usize) -> Vec<String> {
        let mut lines = vec![self.event.render(term_width)];

        let detail_count = self.details.len();
        for (idx, detail) in self.details.iter().enumerate() {
            let is_last = idx + 1 == detail_count;
            let is_only = detail_count == 1;
            let line = detail.render_with_branch(is_last, is_only, term_width);
            lines.push(line);
        }

        lines
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct DetailLineComponent {
    content: String,
    dimmed: bool,
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
    /// The signature key of the current block (for deduplication).
    last_event_key: Option<String>,
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
    /// Number of terminal lines occupied by the last rendered block.
    last_printed_lines: usize,
    /// Terminal lines occupied exclusively by the event line of the last block.
    last_event_lines: usize,
    /// Terminal lines occupied by each detail line of the last block (one entry per detail).
    last_detail_lines: Vec<usize>,
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
            last_event_key: None,
            repeat_count: 0,
            repeat_first_frame: 0,
            repeat_first_ts: Duration::ZERO,
            repeat_last_frame: 0,
            repeat_last_ts: Duration::ZERO,
            last_printed_lines: 0,
            last_event_lines: 0,
            last_detail_lines: Vec::new(),
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
        self.emit_output_block(key, event);
    }

    fn emit_device_error(&mut self, error: &ECDeviceError, correlations: &[ErrorCorrelation]) {
        // A new device error is being emitted — clear ESM tracking
        // (it will be re-set below if this error is itself an ESM error)
        self.clear_esm_tracking();

        let (key, event, frame, ts, corr, esm_info): (
            String,
            EventLine,
            u64,
            Duration,
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
                (key, event, *packet_number, *timestamp, None, None)
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
                (key, event, *packet_number, *timestamp, None, None)
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
                (key, event, d.packet_number, d.timestamp, None, None)
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

                (key, event, d.packet_number, d.timestamp, corr, esm_info)
            }
        };
        self.emit_output_block_with_details(key, event, frame, ts, corr, esm_info, error);
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
        self.emit_output_block(key, event);
    }

    // ─── Core component logic ───

    /// Emit an output block (event line only).
    fn emit_output_block(&mut self, _key: String, event: EventLine) {
        let block = OutputBlock::new(event);
        self.emit_output_block_internal(block);
    }

    /// Emit an output block with detail lines (for device errors).
    fn emit_output_block_with_details(
        &mut self,
        _key: String,
        event: EventLine,
        _frame: u64,
        _ts: Duration,
        corr: Option<WkcErrorDetail>,
        esm_info: Option<(SubdeviceIdentifier, Option<u16>)>,
        error: &ECDeviceError,
    ) {
        let mut block = OutputBlock::new(event);

        // Print detail lines only for the first occurrence (not during repeats).
        if self.repeat_count <= 1 {
            // Add correlation detail if present
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
                let wkc_rendered = wkc_line.render_without_repeat();
                block.add_detail(DetailLine::new(wkc_rendered, false));
            }

            // Add diagnosis if detailed mode
            if self.verbose >= VerboseLevel::Detailed {
                let diagnosis = error.diagnosis();
                block.add_detail(DetailLine::new(diagnosis, true));
            }

            // Add AL Status Code line for ESM errors in detailed mode
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

    /// Internal helper to emit a block with repeat handling.
    fn emit_output_block_internal(&mut self, block: OutputBlock) {
        let term_width = self.terminal_width();
        let event_key = block.event.signature_key();

        // Check if this is a repeat of the last event
        if let Some(ref last_key) = self.last_event_key {
            if last_key == &event_key {
                // Same event repeating — increment counter.
                self.repeat_count += 1;
                self.repeat_last_frame = block.event.frame.unwrap_or(0);
                self.repeat_last_ts = block.event.timestamp.unwrap_or(Duration::ZERO);

                // Throttle: only overwrite the terminal at most once per `overwrite_interval`
                // repeats to avoid flickering from excessive cursor movement.
                let due = self.repeat_count - self.last_overwrite_at >= self.overwrite_interval;
                if due {
                    self.overwrite_repeat_block();
                    self.last_overwrite_at = self.repeat_count;
                }
                return;
            }
        }

        // Different event — output new block.
        self.last_event_key = Some(event_key);
        self.repeat_count = 1;
        self.last_overwrite_at = 0;
        self.repeat_first_frame = block.event.frame.unwrap_or(0);
        self.repeat_first_ts = block.event.timestamp.unwrap_or(Duration::ZERO);
        self.repeat_last_frame = self.repeat_first_frame;
        self.repeat_last_ts = self.repeat_first_ts;

        // Track per-component line counts so we can do targeted rewrites later.
        self.last_event_lines = block.event.line_count(term_width);
        self.last_detail_lines = block
            .details
            .iter()
            .map(|d| d.line_count(term_width))
            .collect();

        // Render and print the block
        let lines = block.render_block(term_width);
        let line_count = lines.len();
        for line in lines {
            println!("{}", line);
        }

        self.last_block = Some(block);
        self.last_printed_lines = line_count;
    }

    /// Rewrite the last output block's event line to show repeat count.
    ///
    /// If the block has no detail lines, the event line is simply rewritten in
    /// place.  When detail lines are present they are left untouched on the
    /// terminal — only the event line above them is updated via cursor movement,
    /// avoiding a full redraw and the flicker it causes.
    fn overwrite_repeat_block(&mut self) {
        if let Some(ref block) = self.last_block.clone() {
            let term_width = self.terminal_width();

            // Build the updated event line.
            let repeated_event_line = block.event.with_repeat_summary(
                self.repeat_count,
                self.repeat_first_frame,
                self.repeat_last_frame,
                self.repeat_first_ts,
                self.repeat_last_ts,
            );

            let detail_lines_total: usize = self.last_detail_lines.iter().sum();

            if detail_lines_total == 0 {
                // Simple case: no details — use LineComponent::rewrite_in_place.
                let new_event_lines =
                    block
                        .event
                        .rewrite_in_place(&repeated_event_line, &self.term, 0, term_width);
                self.last_event_lines = new_event_lines;
                self.last_printed_lines = new_event_lines;
            } else {
                // Details exist below the event.  Move the cursor above the event,
                // rewrite only the event lines, then advance past the details so
                // the cursor ends up back at the bottom.  Details are NOT reprinted.
                let new_event_lines = block.event.rewrite_in_place(
                    &repeated_event_line,
                    &self.term,
                    detail_lines_total,
                    term_width,
                );
                self.last_event_lines = new_event_lines;
                self.last_printed_lines = new_event_lines + detail_lines_total;
            }

            let _ = self.term.flush();
        }
    }

    /// Rewrite the AL Status Code detail line for the last ESM error.
    fn rewrite_al_status_code_detail(&mut self, code: u16) {
        if !self.last_esm_error {
            return;
        }

        if let Some(ref mut block) = self.last_block.clone() {
            if let Some(idx) = self.last_al_status_detail_index {
                if idx < block.details.len() {
                    let al_text = format!("AL Status Code: {}", format_al_status_code(code));
                    let term_width = self.terminal_width();
                    let detail_count = block.details.len();

                    // `lines_below` for this detail = sum of line counts for all details after it.
                    let lines_below_detail: usize = self
                        .last_detail_lines
                        .iter()
                        .skip(idx + 1)
                        .sum();

                    // Determine the rendered form of the updated detail (with correct branch).
                    let is_last = idx + 1 == detail_count;
                    let is_only = detail_count == 1;
                    block.details[idx].update_content(al_text);
                    let new_rendered =
                        block.details[idx].render_with_branch(is_last, is_only, term_width);

                    // Use the DetailLine's rewrite_in_place API.
                    let new_line_count = block.details[idx].rewrite_in_place(
                        &new_rendered,
                        &self.term,
                        lines_below_detail,
                        term_width,
                    );

                    // Update tracked counts.
                    if idx < self.last_detail_lines.len() {
                        self.last_detail_lines[idx] = new_line_count;
                    }
                    let detail_lines_total: usize = self.last_detail_lines.iter().sum();
                    self.last_printed_lines = self.last_event_lines + detail_lines_total;

                    let _ = self.term.flush();
                    self.last_esm_al_status_code = Some(code);
                    self.last_block = Some(block.clone());
                }
            }
        }
    }

    /// Get the current terminal width, with a safe fallback.
    fn terminal_width(&self) -> usize {
        let (_rows, cols) = self.term.size();
        cols as usize
    }

    /// Flush any pending repeat state. Called before printing non-event output.
    fn flush_repeat(&mut self) {
        // If the repeat count advanced past the last overwrite, emit the final state now
        // so the terminal always shows the correct final repeat count.
        if self.repeat_count > 1 && self.repeat_count != self.last_overwrite_at {
            self.overwrite_repeat_block();
        }
        self.last_event_key = None;
        self.repeat_count = 0;
        self.last_overwrite_at = 0;
        self.last_printed_lines = 0;
        self.last_event_lines = 0;
        self.last_detail_lines.clear();
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
}
