
use crate::packet_source::{PcapFileConfig, PcapSource};
use clap::Parser;
use fern::colors::{Color, ColoredLevelConfig};

pub struct Config {
    pub list_interfaces: bool,
    pub verbose: u8,
    pub debug: u8,
    pub pcap_source: PcapSource,
    pub output_file: Option<String>,
}

pub fn parse_args() -> Config {
    #[derive(Parser, Debug)]
    #[command(name = "ecdump", about = "An EtherCAT network dumper", version)]
    struct Cli {
        /// Set the input file path
        #[arg(short, long)]
        file: Option<String>,

        /// Set the output file path
        #[arg(short, long)]
        write: Option<String>,

        /// Set the network interface name
        ///
        /// If not provided, the default interface will be used.
        #[arg(short, long)]
        interface: Option<String>,

        /// Show available network interfaces
        #[arg(short = 'D', long, default_value_t = false)]
        list_interfaces: bool,

        /// Enable verbose reporting (can be used multiple times for increased verbosity)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
        
        #[arg(short, long, hide = true, action = clap::ArgAction::Count)]
        debug: u8,
    }
    let args = Cli::parse();

    let pcap_source = if let Some(file) = args.file {
        let is_pcapng = file.to_lowercase().ends_with(".pcapng");
        PcapSource::File(PcapFileConfig {
            file_path: file,
            is_pcapng,
        })
    } else {
        PcapSource::Interface(args.interface)
    };

    Config {
        list_interfaces: args.list_interfaces,
        verbose: args.verbose,
        debug: args.debug,
        pcap_source,
        output_file: args.write,
    }
}

pub fn set_up_logging(verbose: u8) {
    // use crate::logger::SimpleAsyncLogger;
    // let logger = Box::new(SimpleAsyncLogger::new(
    //     if verbose {
    //         log::LevelFilter::Debug
    //     } else {
    //         log::LevelFilter::Warn
    //     },
    // ));

    // log::set_boxed_logger(logger).unwrap();
    // log::set_max_level(if verbose {
    //     log::LevelFilter::Debug
    // } else {
    //     log::LevelFilter::Warn
    // });

    // use spdlog::{
    //     formatter::{PatternFormatter, pattern},
    //     prelude::*,
    //     sink::{AsyncPoolSink, StdStreamSink, StdStream},
    // };
    // let pattern = pattern!("[{time}.{microsecond} {^{level}}] {payload}{eol}");
    // let stdio_sink = StdStreamSink::builder()
    //     .std_stream(StdStream::Stdout)
    //     .level_filter(if verbose {
    //         LevelFilter::MoreSevereEqual(Level::Debug)
    //     } else {
    //         LevelFilter::MoreSevereEqual(Level::Warn)
    //     })
    //     .build_arc()
    //     .unwrap();
    // stdio_sink.set_formatter(Box::new(PatternFormatter::new(pattern)));
    // let thread_pool = Arc::new(ThreadPool::new().unwrap());
    // let async_sink = AsyncPoolSink::builder().thread_pool(thread_pool).sink(stdio_sink).build_arc().unwrap();
    // let async_logger = Logger::builder()
    //     .sink(async_sink)
    //     .level_filter(if verbose {
    //         LevelFilter::MoreSevereEqual(Level::Debug)
    //     } else {
    //         LevelFilter::MoreSevereEqual(Level::Warn)
    //     })
    //     .build_arc()
    //     .unwrap();
    // spdlog::set_default_logger(async_logger);

    // Configure logger at runtime
    let colors_line = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::Blue)
        .trace(Color::BrightBlack);

    fern::Dispatch::new()
        // Perform allocation-free log formatting
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}] {}",
                chrono::Local::now().format("%H:%M:%S%.6f"),
                colors_line.color(record.level()),
                message
            ))
        })
        .level(if verbose == 0 {
            log::LevelFilter::Off
        } else if verbose == 1 {
            log::LevelFilter::Warn
        } else if verbose == 2 {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Trace
        })
        // Output to stdout, files, and other Dispatch configurations
        .chain(std::io::stdout())
        // .chain(fern::log_file("output.log").unwrap())
        // Apply globally
        .apply()
        .unwrap();

    // use std::io::Write;
    //     env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
    //         .format(|buf, record| {
    //             let timestamp = chrono::Local::now().format("%H:%M:%S%.6f");
    //             // let level_with_color = match record.level() {
    //             //     log::Level::Error => "\x1b[31mERROR\x1b[0m",
    //             //     log::Level::Warn => "\x1b[33mWARN \x1b[0m",
    //             //     log::Level::Info => "\x1b[32mINFO \x1b[0m",
    //             //     log::Level::Debug => "\x1b[34mDEBUG\x1b[0m",
    //             //     log::Level::Trace => "\x1b[35mTRACE\x1b[0m",
    //             // };
    //             let level_with_color = match record.level() {
    //                 log::Level::Error => console::style("ERROR").red().to_string(),
    //                 log::Level::Warn => console::style("WARN ").yellow().to_string(),
    //                 log::Level::Info => console::style("INFO ").green().to_string(),
    //                 log::Level::Debug => console::style("DEBUG").blue().to_string(),
    //                 log::Level::Trace => console::style("TRACE").black().to_string(),
    //             };
    //             writeln!(
    //                 buf,
    //                 "[{} {}] {}",
    //                 timestamp,
    //                 level_with_color,
    //                 record.args()
    //             )
    //         })
    //         .init();
}
