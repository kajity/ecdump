use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use std::sync::mpsc::{Sender, channel};
use std::time::SystemTime;

enum LogEvent {
    Message(String),
    Flush,
    Shutdown,
}

pub struct SimpleAsyncLogger {
    sender: Mutex<Sender<LogEvent>>,
    log_level: LevelFilter,
}

impl SimpleAsyncLogger {
    pub fn new(log_level: LevelFilter) -> Self {
        let (tx, rx) = channel::<LogEvent>();

        std::thread::spawn(move || {
            let mut writer = BufWriter::new(std::io::stdout());

            loop {
                match rx.recv() {
                    Ok(LogEvent::Message(msg)) => {
                        // ここで重いI/O処理を行う
                        let _ = writeln!(writer, "{}", msg);
                    }
                    Ok(LogEvent::Flush) => {
                        let _ = writer.flush();
                    }
                    Ok(LogEvent::Shutdown) | Err(_) => {
                        let _ = writer.flush();
                        break;
                    }
                }
            }
        });

        SimpleAsyncLogger {
            sender: Mutex::new(tx),
            log_level,
        }
    }
}

impl log::Log for SimpleAsyncLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.log_level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let msg = format!(
                "{} - [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.6f"),
                record.level(),
                record.args()
            );

            // キューに投げるだけ（高速）
            if let Ok(tx) = self.sender.lock() {
                let _ = tx.send(LogEvent::Message(msg));
            }
        }
    }

    fn flush(&self) {
        if let Ok(tx) = self.sender.lock() {
            let _ = tx.send(LogEvent::Flush);
        }
    }
}
