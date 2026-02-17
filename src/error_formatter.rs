use crossterm::execute;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use std::io::stdout;
use std::time::Duration;

use crate::analyzer::{ECDeviceError, ECError};
use ecdump::ec_packet::{ECCommand, ECPacketError};
use ecdump::subdevice::ESMError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerboseLevel {
    Brief = 0,
    Normal = 1,
    Detailed = 2,
    Debug = 3,
}

impl VerboseLevel {
    pub fn from_u8(level: u8) -> Self {
        match level {
            0 => VerboseLevel::Brief,
            1 => VerboseLevel::Normal,
            2 => VerboseLevel::Detailed,
            _ => VerboseLevel::Debug,
        }
    }
}

pub struct ErrorFormatter {
    verbose: VerboseLevel,
}

impl ErrorFormatter {
    pub fn new(verbose_level: u8) -> Self {
        ErrorFormatter {
            verbose: VerboseLevel::from_u8(verbose_level),
        }
    }

    pub fn report(&self, error: ECError) {
        match error {
            ECError::InvalidDatagram(e) => {
                self.print_datagram_error(&e);
            }
            ECError::DeviceError(errors) => {
                for err in errors {
                    self.print_device_error(&err);
                }
            }
        }
    }

    fn print_datagram_error(&self, error: &ECPacketError) {
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("❌ Error"),
            ResetColor,
        );
        println!(": Invalid EtherCAT datagram");

        if self.verbose >= VerboseLevel::Normal {
            println!("   Details: {:?}", error);
        }
    }

    fn print_device_error(&self, error: &ECDeviceError) {
        match error {
            ECDeviceError::InvalidAutoIncrementAddress(addr) => {
                self.print_invalid_auto_increment_address(*addr);
            }
            ECDeviceError::InvalidConfiguredAddress(addr) => {
                self.print_invalid_configured_address(*addr);
            }
            ECDeviceError::InvalidWkc {
                packet_number,
                command,
                from_main,
                timestamp,
                expected,
                actual,
            } => {
                self.print_invalid_wkc(
                    *packet_number,
                    command,
                    *from_main,
                    *timestamp,
                    *expected,
                    *actual,
                );
            }
            ECDeviceError::ESMError(esm_error) => {
                self.print_esm_error(esm_error);
            }
        }
    }

    fn print_invalid_auto_increment_address(&self, addr: u16) {
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::Yellow),
            Print("⚠️  Warning"),
            ResetColor,
        );
        println!(": Invalid auto-increment address");

        if self.verbose >= VerboseLevel::Normal {
            println!("   Address: {:#06x}", addr);
        }
    }

    fn print_invalid_configured_address(&self, addr: u16) {
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::Yellow),
            Print("⚠️  Warning"),
            ResetColor,
        );
        println!(": Invalid configured address");

        if self.verbose >= VerboseLevel::Normal {
            println!("   Address: {:#06x}", addr);
        }
    }

    fn print_invalid_wkc(
        &self,
        packet_number: u64,
        command: &ECCommand,
        from_main: bool,
        timestamp: Duration,
        expected: u16,
        actual: u16,
    ) {
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("❌ Error"),
            ResetColor,
        );
        println!(": Working Counter (WKC) Mismatch");

        if self.verbose >= VerboseLevel::Brief {
            println!("   Frame #: {}", packet_number);
            println!("   Command: {}", command.as_str());
            let direction = if from_main {
                "Main → Device"
            } else {
                "Device → Main"
            };
            println!("   Direction: {}", direction);

            if self.verbose >= VerboseLevel::Normal {
                println!("   Timestamp: {:.3}s", timestamp.as_secs_f64());
                println!("   Expected WKC: {}", expected);
                println!("   Actual WKC: {}", actual);
                println!("   Difference: {}", (expected as i32 - actual as i32).abs());
            }

            if self.verbose >= VerboseLevel::Detailed {
                println!("   Severity: {}", self.classify_wkc_error(expected, actual));
            }
        }
    }

    fn print_esm_error(&self, esm_error: &ESMError) {
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("❌ Error"),
            ResetColor,
        );
        println!(": ESM (EtherCAT State Machine) Error");

        if self.verbose >= VerboseLevel::Normal {
            println!("   Details: {:?}", esm_error);
        }
    }

    fn classify_wkc_error(&self, expected: u16, actual: u16) -> &'static str {
        let diff = (expected as i32 - actual as i32).abs();
        match diff {
            0 => "None",
            1 => "Minor (1 device affected)",
            2..=3 => "Moderate (2-3 devices affected)",
            _ => "Critical (multiple devices affected)",
        }
    }

    pub fn print_summary(&self, total_frames: u64, total_errors: usize) {
        println!();
        if total_errors == 0 {
            let _ = execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("✓ Success"),
                ResetColor,
            );
            println!(": No errors detected in {} frames", total_frames);
        } else {
            let _ = execute!(
                stdout(),
                SetForegroundColor(Color::Red),
                Print("✗ Issues Found"),
                ResetColor,
            );
            println!(": {} error(s) in {} frames", total_errors, total_frames);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verbose_level_ordering() {
        assert!(VerboseLevel::Brief < VerboseLevel::Normal);
        assert!(VerboseLevel::Normal < VerboseLevel::Detailed);
        assert!(VerboseLevel::Detailed < VerboseLevel::Debug);
    }

    #[test]
    fn test_verbose_level_from_u8() {
        assert_eq!(VerboseLevel::from_u8(0), VerboseLevel::Brief);
        assert_eq!(VerboseLevel::from_u8(1), VerboseLevel::Normal);
        assert_eq!(VerboseLevel::from_u8(2), VerboseLevel::Detailed);
        assert_eq!(VerboseLevel::from_u8(3), VerboseLevel::Debug);
        assert_eq!(VerboseLevel::from_u8(99), VerboseLevel::Debug);
    }
}
