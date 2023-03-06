use std::io;
use std::io::Write;
use std::sync::Mutex;

use anyhow::{anyhow, Result};
use log4rs::append::file::FileAppender;
use log4rs::append::{console::ConsoleAppender, Append};
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::{pattern::PatternEncoder, Encode};
use log4rs::Handle;

use crate::config;

static HANDLE: Mutex<Option<Handle>> = Mutex::new(None);

#[cfg(any(target_os = "ios", target_os = "android", target_os = "macos"))]
mod mobile {
    use super::*;

    #[derive(Debug)]
    pub(crate) struct MobileConsoleAppender {
        pub writer: Mutex<MobileConsoleWriter>,
        pub encoder: Box<dyn Encode>,
    }

    impl log4rs::append::Append for MobileConsoleAppender {
        fn append(&self, record: &log::Record<'_>) -> Result<()> {
            // No need flush with the current mobile console writer impl
            self.encoder.encode(&mut *self.writer.lock().unwrap(), record)
        }

        fn flush(&self) {}
    }

    #[derive(Debug)]
    pub(crate) struct MobileConsoleWriter(pub crate::mobile::logger::ConsoleWriter);

    impl log4rs::encode::Write for MobileConsoleWriter {
        fn set_style(&mut self, _style: &log4rs::encode::Style) -> io::Result<()> {
            Ok(())
        }
    }

    impl Write for MobileConsoleWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
}

#[derive(Debug)]
struct ModuleFilter;

impl log4rs::filter::Filter for ModuleFilter {
    fn filter(&self, record: &log::Record<'_>) -> log4rs::filter::Response {
        if let Some(m) = record.module_path() {
            if m.starts_with("leaf") || m.starts_with("netstack_lwip") || m.starts_with("rust_tun")
            {
                return log4rs::filter::Response::Neutral;
            } else {
                if record.level() <= log::Level::Warn {
                    return log4rs::filter::Response::Neutral;
                } else {
                    return log4rs::filter::Response::Reject;
                }
            }
        }
        log4rs::filter::Response::Neutral
    }
}

pub fn setup_logger(config: &protobuf::MessageField<crate::config::Log>) -> Result<()> {
    let Some(config) = config.as_ref() else {
        return Err(anyhow!("empty log config"));
    };
    let loglevel = match config.level.unwrap() {
        config::log::Level::TRACE => log::LevelFilter::Trace,
        config::log::Level::DEBUG => log::LevelFilter::Debug,
        config::log::Level::INFO => log::LevelFilter::Info,
        config::log::Level::WARN => log::LevelFilter::Warn,
        config::log::Level::ERROR => log::LevelFilter::Error,
    };
    let mut builder = Config::builder();
    let mut root = Root::builder();
    let appender = Appender::builder().filter(Box::new(ModuleFilter));
    let encoder = if *crate::option::LOG_NO_COLOR {
        PatternEncoder::new("[{d(%Y-%m-%d %H:%M:%S)}][{l}] {m}{n}")
    } else {
        PatternEncoder::new("[{d(%Y-%m-%d %H:%M:%S)}][{h({l})}] {m}{n}")
    };
    match config.output.unwrap() {
        config::log::Output::CONSOLE => {
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            let console = Box::new(
                ConsoleAppender::builder()
                    .encoder(Box::new(encoder))
                    .build(),
            );
            #[cfg(any(target_os = "ios", target_os = "android"))]
            let console = Box::new(mobile::MobileConsoleAppender {
                writer: Mutex::new(mobile::MobileConsoleWriter(
                    crate::mobile::logger::ConsoleWriter::default(),
                )),
                encoder: Box::new(encoder),
            });
            #[cfg(target_os = "macos")]
            let console: Box<dyn Append> = {
                if *crate::option::LOG_CONSOLE_OUT {
                    Box::new(mobile::MobileConsoleAppender {
                        writer: Mutex::new(mobile::MobileConsoleWriter(
                            crate::mobile::logger::ConsoleWriter::default(),
                        )),
                        encoder: Box::new(encoder),
                    })
                } else {
                    Box::new(
                        ConsoleAppender::builder()
                            .encoder(Box::new(encoder))
                            .build(),
                    )
                }
            };
            builder = builder.appender(appender.build("console", console));
            root = root.appender("console");
        }
        config::log::Output::FILE => {
            let file_out = FileAppender::builder()
                .encoder(Box::new(encoder))
                .build(&config.output_file)
                .unwrap();
            builder = builder.appender(appender.build("file", Box::new(file_out)));
            root = root.appender("file");
        }
    }
    let config = builder.build(root.build(loglevel)).unwrap();
    let mut handle = HANDLE.lock().unwrap();
    if let Some(handle) = handle.as_ref() {
        handle.set_config(config);
    } else {
        *handle = Some(log4rs::init_config(config).unwrap());
    }
    Ok(())
}
