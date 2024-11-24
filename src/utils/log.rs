use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};
use std::env;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Once;
use chrono::Local;

static INIT: Once = Once::new();
static LOG_LEVEL: AtomicUsize = AtomicUsize::new(LevelFilter::Info as usize);
static SHOW_TIME: AtomicBool = AtomicBool::new(false);

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= LevelFilter::from_usize(LOG_LEVEL.load(Ordering::Relaxed)).unwrap()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level = record.level();
            let level_str = match level {
                Level::Trace => "TRACE",
                Level::Debug => "DEBUG",
                Level::Info => "INFO",
                Level::Warn => "WARN",
                Level::Error => "ERROR",
            };

            let time_str = if SHOW_TIME.load(Ordering::Relaxed) {
                format!("[{}] ", Local::now().format("%Y-%m-%d %H:%M:%S"))
            } else {
                String::new()
            };

            println!("{}[{}] {}", time_str, level_str, record.args());
        }
    }

    fn flush(&self) {}
}

pub fn log_init() -> Result<(), SetLoggerError> {
    INIT.call_once(|| {
        let log_level_str = env::var("DUNE_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        let log_level = match log_level_str.as_str() {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => LevelFilter::Info,
        };
        LOG_LEVEL.store(log_level as usize, Ordering::Relaxed);

        let show_time_str = env::var("DUNE_LOG_SHOW_TIME").unwrap_or_else(|_| "false".to_string());
        let show_time = show_time_str == "true";
        SHOW_TIME.store(show_time, Ordering::Relaxed);

        log::set_logger(&SimpleLogger).unwrap();
        log::set_max_level(log_level);
    });
    Ok(())
}

fn log_test() {
    log_init().unwrap();
    log::info!("This is an info message");
    log::warn!("This is a warning message");
    log::error!("This is an error message");
}
