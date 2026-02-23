use crossterm::QueueableCommand;
use crossterm::cursor::MoveUp;
use crossterm::execute;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use crossterm::terminal::{Clear, ClearType};
use std::collections::{HashMap, VecDeque};
use std::io::{Write, stdout};
use std::time::Duration;

use crate::analyzer::{ECDeviceError, ECError, ErrorAggregation, ErrorCorrelation};
use ecdump::ec_packet::ECPacketError;
use ecdump::subdevice::SubdeviceIdentifier;
use log::info;

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

#[derive(Debug)]
pub struct ErrorStats {
    pub wkc_errors: usize,
    pub esm_errors: usize,
    pub address_errors: usize,
    pub correlated_errors: usize,
}

#[derive(Debug, Clone)]
struct ErrorEntry {
    subdevice_id: SubdeviceIdentifier,
    error_type: String,
    count: usize,
    last_frame: u64,
    last_timestamp: Duration,
}

pub struct ErrorFormatter {
    verbose: VerboseLevel,
    error_queue: VecDeque<String>,
    last_output_lines: usize,
    current_burst_count: usize,
    showing_progress: bool,
    start_time: std::time::Instant,
    error_table: HashMap<String, ErrorEntry>, // key: "subdevice_id:error_type"
    table_displayed: bool,
}

impl ErrorFormatter {
    pub fn new(verbose_level: u8) -> Self {
        ErrorFormatter {
            verbose: VerboseLevel::from_u8(verbose_level),
            error_queue: VecDeque::new(),
            last_output_lines: 0,
            current_burst_count: 0,
            showing_progress: false,
            start_time: std::time::Instant::now(),
            error_table: HashMap::new(),
            table_displayed: false,
        }
    }

    pub fn report(&mut self, error: ECError) {
        if self.verbose == VerboseLevel::Nothing {
            return;
        }

        match error {
            ECError::InvalidDatagram(e) => {
                self.queue_datagram_error(&e);
                self.flush_queue();
            }
            ECError::DeviceError(errors) => {
                for err in errors {
                    self.handle_device_error(&err);
                }
            }
        }
    }

    fn handle_device_error(&mut self, error: &ECDeviceError) {
        // For ESM errors, aggregate into a table
        if let ECDeviceError::ESMError(detail) = error {
            let packet_number = detail.packet_number;
            let timestamp = detail.timestamp;
            let subdevice_id = &detail.subdevice_id;
            let esm_err = &detail.error;

            let error_type = format!("{:?}", esm_err);
            let key = format!("{}:{}", subdevice_id, error_type);

            if let Some(entry) = self.error_table.get_mut(&key) {
                entry.count += 1;
                entry.last_frame = packet_number;
                entry.last_timestamp = timestamp;
            } else {
                self.error_table.insert(
                    key.clone(),
                    ErrorEntry {
                        subdevice_id: subdevice_id.clone(),
                        error_type: error_type.clone(),
                        count: 1,
                        last_frame: packet_number,
                        last_timestamp: timestamp,
                    },
                );
            }

            // テーブルを更新表示
            self.update_error_table();
        } else {
            // ESM以外のエラーは通常通り出力
            self.queue_device_error(error);
            self.flush_queue();
        }
    }

    fn update_error_table(&mut self) {
        if self.verbose == VerboseLevel::Nothing || self.error_table.is_empty() {
            return;
        }

        let mut stdout = stdout();

        // clear previous table output
        self.clear_last_output();

        // table header
        let header =
            "┌────────────────────────────--────────────────────────────────────────────────┐
│ 📊 ESM Error Summary (Live)                                                  │
├──────────────────┬────────────────────┬───────┬─-──────────┬─────────────────┤
│ Subdevice        │ Error Type         │ Count │ Last Frame │ Last Time (s)   │
├──────────────────┼────────────────────┼───────┼───────────-┼─────────────────┤
";
        stdout.queue(Print(header)).ok();
        let mut header_lines = 5;

        // エラーエントリをソート（subdevice_id順）
        let mut entries: Vec<_> = self.error_table.values().collect();
        entries.sort_by_key(|e| (&e.subdevice_id, &e.error_type));

        for entry in entries {
            let subdev_str = entry.subdevice_id.to_string();
            let subdev_display = if subdev_str.len() > 16 {
                format!("{}...", &subdev_str[..13])
            } else {
                subdev_str
            };

            let error_display = if entry.error_type.len() > 18 {
                format!("{}...", &entry.error_type[..15])
            } else {
                entry.error_type.clone()
            };

            stdout
                .queue(Print(format!(
                    "│ {:<16} │ {:<18} │ {:>5} │ {:>10} │ {:>15.3} │\n",
                    subdev_display,
                    error_display,
                    entry.count,
                    entry.last_frame,
                    entry.last_timestamp.as_secs_f64()
                )))
                .ok();
            header_lines += 1;
        }

        println!(
            "└──────────────────┴────────────────────┴───────┴──-─────────┴─────────────────┘"
        );
        header_lines += 1;

        self.last_output_lines = header_lines;
        self.table_displayed = true;
        stdout.flush().ok();
    }

    pub fn finalize_table(&mut self) {
        if self.table_displayed && !self.error_table.is_empty() {
            // 最終的なテーブル表示（クリアしない）
            println!(); // 改行して固定
            self.table_displayed = false;
        }
    }

    pub fn report_aggregations(&mut self, aggregations: &[ErrorAggregation]) {
        if self.verbose == VerboseLevel::Nothing {
            return;
        }

        // テーブル表示を終了
        self.finalize_table();

        for agg in aggregations {
            if agg.count > 1 {
                self.print_aggregated_error(agg);
            } else {
                self.print_single_error(&agg.error);
            }
        }
    }

    pub fn report_correlations(&mut self, correlations: &[ErrorCorrelation]) {
        info!("Reporting {} error correlations", correlations.len());
        if self.verbose == VerboseLevel::Nothing || correlations.is_empty() {
            return;
        }

        println!();
        self.print_separator();
        self.print_colored("🔗 Error Correlations", Color::Yellow);
        println!();

        for (i, corr) in correlations.iter().enumerate() {
            if let Some(esm_err) = &corr.esm_error {
                println!(
                    "  {}. ESM Error correlated with WKC Error (gap: {} frames)",
                    i + 1,
                    corr.frame_gap
                );

                if self.verbose >= VerboseLevel::Detailed {
                    println!(
                        "     Analysis: ESM error likely resulted from preceding WKC mismatch"
                    );
                    if let ECDeviceError::InvalidWkc(detail) = &corr.wkc_error {
                        let dev_str = detail
                            .subdevice_id
                            .as_ref()
                            .map(|s| format!(" [{}]", s))
                            .unwrap_or_default();
                        println!(
                            "     WKC: {}{} (expected: {}, actual: {})",
                            detail.command.as_str(),
                            dev_str,
                            detail.expected,
                            detail.actual
                        );
                    }
                    println!("     ESM: {:?}", esm_err);
                }
            }
        }
        println!();
    }

    fn queue_datagram_error(&mut self, error: &ECPacketError) {
        let msg = format!("❌ EtherCAT Datagram Error: {:?}", error);
        self.error_queue.push_back(msg);
    }

    fn queue_device_error(&mut self, error: &ECDeviceError) {
        let msg = match error {
            ECDeviceError::InvalidAutoIncrementAddress {
                packet_number,
                timestamp,
                command,
                address,
            } => {
                format!(
                    "⚠️  #{} [{:.3}s] {}: Invalid Auto-Increment Addr {:#06x}",
                    packet_number,
                    timestamp.as_secs_f64(),
                    command.as_str(),
                    address,
                )
            }
            ECDeviceError::InvalidConfiguredAddress {
                packet_number,
                timestamp,
                command,
                address,
            } => {
                format!(
                    "⚠️  #{} [{:.3}s] {}: Invalid Configured Addr {:#06x}",
                    packet_number,
                    timestamp.as_secs_f64(),
                    command.as_str(),
                    address,
                )
            }
            ECDeviceError::InvalidWkc(d) => {
                let dev_str = d
                    .subdevice_id
                    .as_ref()
                    .map(|s| format!(" [{}]", s))
                    .unwrap_or_default();
                format!(
                    "❌ #{} [{:.3}s] WKC Mismatch: {}{} (exp: {}, got: {})",
                    d.packet_number,
                    d.timestamp.as_secs_f64(),
                    d.command.as_str(),
                    dev_str,
                    d.expected,
                    d.actual
                )
            }
            ECDeviceError::ESMError(d) => {
                format!(
                    "💥 #{} [{:.3}s] ESM Error [{}]: {:?}",
                    d.packet_number,
                    d.timestamp.as_secs_f64(),
                    d.subdevice_id,
                    d.error
                )
            }
        };
        self.error_queue.push_back(msg);
    }

    fn flush_queue(&mut self) {
        while let Some(msg) = self.error_queue.pop_front() {
            println!("{}", msg);
        }
    }

    fn print_aggregated_error(&self, agg: &ErrorAggregation) {
        match &agg.error {
            ECDeviceError::InvalidWkc(d) => {
                let dev_str = d
                    .subdevice_id
                    .as_ref()
                    .map(|s| format!(" [{}]", s))
                    .unwrap_or_default();
                self.print_colored("📈 Aggregated WKC Error", Color::Red);
                println!(" ({}{})", d.command.as_str(), dev_str);

                let rate = agg.count as f64
                    / (agg.last_timestamp.as_secs_f64() - agg.first_timestamp.as_secs_f64())
                        .max(0.001);

                println!("   Occurrences: {} (rate: {:.1}/s)", agg.count, rate);
                println!(
                    "   Frame range: #{} → #{}",
                    agg.first_packet_number, agg.last_packet_number
                );

                if self.verbose >= VerboseLevel::Detailed {
                    println!("   Expected WKC: {}, Actual WKC: {}", d.expected, d.actual);
                    println!(
                        "   Time span: {:.3}s → {:.3}s",
                        agg.first_timestamp.as_secs_f64(),
                        agg.last_timestamp.as_secs_f64()
                    );
                    println!("   Impact: {}", self.classify_error_impact(agg.count));
                }

                if agg.related_wkc_error.is_some() {
                    println!("   🔗 Related to previous WKC error");
                }
            }
            ECDeviceError::ESMError(d) => {
                self.print_colored("💥 Aggregated ESM Errors", Color::Red);
                println!(" [{}]", d.subdevice_id);
                println!("   Error Type: {:?}", d.error);
                println!("   Occurrences: {}", agg.count);
                println!(
                    "   Frame range: #{} → #{}",
                    agg.first_packet_number, agg.last_packet_number
                );
                println!("   ⚠️  Multiple state machine failures detected");

                if agg.related_wkc_error.is_some() {
                    println!("   🔗 Likely caused by WKC errors (see correlation analysis)");
                }
            }
            _ => {
                self.print_single_error(&agg.error);
            }
        }
    }

    fn print_single_error(&self, error: &ECDeviceError) {
        match error {
            ECDeviceError::InvalidAutoIncrementAddress {
                packet_number,
                timestamp,
                command,
                address,
            } => {
                self.print_colored("⚠️  Address Error", Color::Yellow);
                println!(
                    ": #{} [{:.3}s] {} Invalid auto-increment {:#06x}",
                    packet_number,
                    timestamp.as_secs_f64(),
                    command.as_str(),
                    address,
                );
            }
            ECDeviceError::InvalidConfiguredAddress {
                packet_number,
                timestamp,
                command,
                address,
            } => {
                self.print_colored("⚠️  Address Error", Color::Yellow);
                println!(
                    ": #{} [{:.3}s] {} Invalid configured {:#06x}",
                    packet_number,
                    timestamp.as_secs_f64(),
                    command.as_str(),
                    address,
                );
            }
            ECDeviceError::InvalidWkc(d) => {
                let dev_str = d
                    .subdevice_id
                    .as_ref()
                    .map(|s| format!(" [{}]", s))
                    .unwrap_or_default();
                self.print_colored("❌ WKC Error", Color::Red);
                println!(
                    ": #{} [{:.3}s] {}{}",
                    d.packet_number,
                    d.timestamp.as_secs_f64(),
                    d.command.as_str(),
                    dev_str
                );

                if self.verbose >= VerboseLevel::Normal {
                    println!("   Expected: {}, Actual: {}", d.expected, d.actual);
                    println!("   Cause: {}", self.analyze_wkc_cause(d.expected, d.actual));
                }
            }
            ECDeviceError::ESMError(d) => {
                self.print_colored("💥 ESM Error", Color::Red);
                println!(
                    ": #{} [{:.3}s] {} [{}]",
                    d.packet_number,
                    d.timestamp.as_secs_f64(),
                    d.command.as_str(),
                    d.subdevice_id
                );

                if self.verbose >= VerboseLevel::Normal {
                    println!("   Error: {:?}", d.error);
                    println!("   Impact: State machine failure - device may be offline");
                }
            }
        }
    }

    fn classify_error_impact(&self, count: usize) -> &'static str {
        match count {
            1..=5 => "Low impact - isolated errors",
            6..=20 => "Medium impact - recurring issues",
            21..=50 => "High impact - significant communication problems",
            _ => "Critical impact - major network failure",
        }
    }

    fn analyze_wkc_cause(&self, expected: u16, actual: u16) -> &'static str {
        if actual == 0 {
            "Complete communication failure - no device responses"
        } else if actual < expected {
            "Partial communication failure - some devices not responding"
        } else if actual > expected {
            "Unexpected responses - possible address conflicts"
        } else {
            "Working counter mismatch"
        }
    }

    fn print_colored(&self, text: &str, color: Color) {
        let _ = execute!(stdout(), SetForegroundColor(color), Print(text), ResetColor,);
    }

    fn print_separator(&self) {
        println!("{}", "─".repeat(80));
    }

    fn clear_last_output(&mut self) {
        if self.last_output_lines > 0 {
            for _ in 0..self.last_output_lines {
                let _ = execute!(stdout(), MoveUp(1), Clear(ClearType::CurrentLine));
            }
            self.last_output_lines = 0;
        }
    }

    pub fn print_summary(
        &mut self,
        total_frames: u64,
        aggregations: &[ErrorAggregation],
        correlations: &[ErrorCorrelation],
    ) {
        // verbose level 0のときは何も出力しない
        if self.verbose == VerboseLevel::Nothing {
            return;
        }

        // テーブル表示を終了
        self.finalize_table();

        let stats = self.calculate_stats(aggregations);
        let total_errors: usize = aggregations.iter().map(|a| a.count).sum();

        println!();
        self.print_separator();

        if total_errors == 0 {
            self.print_colored("✓ Analysis Complete", Color::Green);
            println!(": No errors detected");
            println!("   Frames analyzed: {}", total_frames);
        } else {
            self.print_colored("⚡ Analysis Summary", Color::Cyan);
            println!();
            println!("   Frames analyzed: {}", total_frames);
            println!(
                "   Total errors: {} (rate: {:.2}%)",
                total_errors,
                (total_errors as f64 / total_frames as f64) * 100.0
            );

            if self.verbose >= VerboseLevel::Normal {
                println!();
                println!("📊 Error Breakdown:");
                println!("   WKC Errors: {}", stats.wkc_errors);
                println!("   ESM Errors: {}", stats.esm_errors);
                println!("   Address Errors: {}", stats.address_errors);
                if stats.correlated_errors > 0 {
                    println!("   Correlated Error Pairs: {}", stats.correlated_errors);
                }

                if self.verbose >= VerboseLevel::Detailed {
                    self.print_detailed_analysis(&stats, total_frames, correlations);
                }
            }
        }

        self.print_separator();
    }

    fn calculate_stats(&self, aggregations: &[ErrorAggregation]) -> ErrorStats {
        let mut stats = ErrorStats {
            wkc_errors: 0,
            esm_errors: 0,
            address_errors: 0,
            correlated_errors: 0,
        };

        for agg in aggregations {
            match &agg.error {
                ECDeviceError::InvalidWkc(_) => stats.wkc_errors += agg.count,
                ECDeviceError::ESMError(_) => {
                    stats.esm_errors += agg.count;
                    if agg.related_wkc_error.is_some() {
                        stats.correlated_errors += 1;
                    }
                }
                ECDeviceError::InvalidAutoIncrementAddress { .. }
                | ECDeviceError::InvalidConfiguredAddress { .. } => {
                    stats.address_errors += agg.count
                }
            }
        }

        stats
    }

    fn print_detailed_analysis(
        &self,
        stats: &ErrorStats,
        total_frames: u64,
        correlations: &[ErrorCorrelation],
    ) {
        println!();
        println!("🔍 Detailed Analysis:");

        if stats.wkc_errors > 0 {
            println!("   • WKC errors indicate communication issues between master and devices");
            println!("     Check: cable integrity, device power, network topology");
        }

        if stats.esm_errors > 0 {
            println!("   • ESM errors indicate state machine failures in EtherCAT devices");
            println!("     Check: device configuration, state transitions, error recovery");
        }

        if !correlations.is_empty() {
            println!("   • Error correlations suggest WKC failures leading to ESM errors");
            println!("     Focus: Address the root WKC causes to prevent ESM failures");
        }

        if stats.address_errors > 0 {
            println!("   • Address errors suggest network topology or configuration issues");
            println!("     Check: device addressing, auto-increment configuration");
        }

        let error_rate = (stats.wkc_errors + stats.esm_errors) as f64 / total_frames as f64 * 100.0;
        if error_rate > 1.0 {
            println!(
                "   ⚠️  High error rate ({:.2}%) - immediate attention required",
                error_rate
            );
        } else if error_rate > 0.1 {
            println!(
                "   ⚠️  Moderate error rate ({:.2}%) - investigation recommended",
                error_rate
            );
        }
    }
}

impl Drop for ErrorFormatter {
    fn drop(&mut self) {
        self.finalize_table();
        self.flush_queue();
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
    fn test_error_stats_calculation() {
        let formatter = ErrorFormatter::new(1);
        let aggregations = vec![];
        let stats = formatter.calculate_stats(&aggregations);
        assert_eq!(stats.wkc_errors, 0);
        assert_eq!(stats.esm_errors, 0);
    }
}
