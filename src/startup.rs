use crate::packet_source::{PcapFileConfig, PcapSource};
use clap::Parser;
use fern::colors::{Color, ColoredLevelConfig};

pub struct Config {
    pub verbose: bool,
    pub pcap_source: PcapSource,
    pub output_file: Option<String>,
}

pub fn parse_args() -> Config {
    #[derive(Parser, Debug)]
    #[command(name = "ecdump", about = "An EtherCAT network dumper", version)]
    struct Args {
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

        /// Enable verbose logging
        #[arg(short, long, default_value_t = false)]
        verbose: bool,
    }
    let args = Args::parse();

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
        verbose: args.verbose,
        pcap_source,
        output_file: args.write,
    }
}

pub fn set_up_logging(verbose: bool) {
    // Configure logger at runtime
    let colors_line = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::Blue)
        .trace(Color::BrightBlack);

    let _ = fern::Dispatch::new()
        // Perform allocation-free log formatting
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}] {}",
                chrono::Local::now().format("%H:%M:%S%.6f"),
                colors_line.color(record.level()),
                message
            ))
        })
        .level(if verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Warn
        })
        .level_for("hyper", log::LevelFilter::Info)
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
    //             let level_with_color = match record.level() {
    //                 log::Level::Error => "\x1b[31mERROR\x1b[0m",
    //                 log::Level::Warn => "\x1b[33mWARN \x1b[0m",
    //                 log::Level::Info => "\x1b[32mINFO \x1b[0m",
    //                 log::Level::Debug => "\x1b[34mDEBUG\x1b[0m",
    //                 log::Level::Trace => "\x1b[35mTRACE\x1b[0m",
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
