use std::fs::OpenOptions;
use std::path::Path;
use std::sync::RwLock;

use anyhow::Result;
use tracing::field::Visit;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    filter::{filter_fn, LevelFilter},
    fmt,
    layer::{Layer, Layered},
    prelude::*,
    registry::Registry,
    reload,
    reload::Handle,
};

use crate::config;

type FilterHandle = Handle<LevelFilter, Registry>;

#[derive(Clone, Copy)]
enum LogFormatMode {
    Full,
    Compact,
}

#[derive(Clone, Copy)]
struct LogEventFormat {
    mode: LogFormatMode,
}

impl<S, N> tracing_subscriber::fmt::format::FormatEvent<S, N> for LogEventFormat
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'writer> tracing_subscriber::fmt::format::FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        match self.mode {
            LogFormatMode::Full => {
                tracing_subscriber::fmt::format::Format::default().format_event(ctx, writer, event)
            }
            LogFormatMode::Compact => {
                struct MessageVisitor {
                    message: Option<String>,
                }

                impl Visit for MessageVisitor {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        if field.name() == "message" {
                            self.message = Some(format!("{value:?}"));
                        }
                    }

                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        if field.name() == "message" {
                            self.message = Some(value.to_string());
                        }
                    }
                }

                let mut visitor = MessageVisitor { message: None };
                event.record(&mut visitor);

                if let Some(mut message) = visitor.message {
                    if message.starts_with('\"') && message.ends_with('\"') && message.len() >= 2 {
                        message = message[1..message.len() - 1].to_string();
                    }
                    std::fmt::Write::write_str(&mut writer, &message)?;
                } else {
                    std::fmt::Write::write_str(&mut writer, "")?;
                }

                std::fmt::Write::write_str(&mut writer, "\n")?;
                Ok(())
            }
        }
    }
}

type WriterLayer = fmt::Layer<
    Layered<reload::Layer<LevelFilter, Registry>, Registry>,
    tracing_subscriber::fmt::format::DefaultFields,
    LogEventFormat,
    tracing_appender::non_blocking::NonBlocking,
>;
type WriterHandle = Handle<WriterLayer, Layered<reload::Layer<LevelFilter, Registry>, Registry>>;

struct HandleController {
    filter: FilterHandle,
    writer: WriterHandle,
    writer_guard: WorkerGuard,
}

impl HandleController {
    pub fn new(filter: FilterHandle, writer: WriterHandle, writer_guard: WorkerGuard) -> Self {
        Self {
            filter,
            writer,
            writer_guard,
        }
    }

    pub fn reload(
        &mut self,
        filter: LevelFilter,
        writer: WriterLayer,
        writer_guard: WorkerGuard,
    ) -> Result<(), reload::Error> {
        self.filter.modify(|f| *f = filter)?;
        self.writer.reload(writer)?;
        self.writer_guard = writer_guard;
        Ok(())
    }
}

static HANDLE: RwLock<Option<HandleController>> = RwLock::new(None);

fn get_writer(config: &config::Log) -> Result<(WriterLayer, WorkerGuard)> {
    let mode = match config.format.unwrap() {
        config::log::Format::COMPACT => LogFormatMode::Compact,
        _ => LogFormatMode::Full,
    };

    Ok(match config.output.unwrap() {
        config::log::Output::CONSOLE => {
            #[cfg(target_os = "macos")]
            {
                if *crate::option::LOG_CONSOLE_OUT {
                    let writer = crate::mobile::logger::ConsoleWriter::default();
                    let (writer, writer_guard) = tracing_appender::non_blocking(writer);
                    let writer = fmt::Layer::default()
                        .with_ansi(false)
                        .with_writer(writer)
                        .event_format(LogEventFormat { mode });
                    (writer, writer_guard)
                } else {
                    let (writer, writer_guard) = tracing_appender::non_blocking(std::io::stdout());
                    let writer = fmt::Layer::default()
                        .with_writer(writer)
                        .event_format(LogEventFormat { mode });
                    (writer, writer_guard)
                }
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            {
                let (writer, writer_guard) = tracing_appender::non_blocking(std::io::stdout());
                let writer = fmt::Layer::default()
                    .with_writer(writer)
                    .event_format(LogEventFormat { mode });
                (writer, writer_guard)
            }
            #[cfg(any(target_os = "ios", target_os = "android"))]
            {
                let writer = crate::mobile::logger::ConsoleWriter::default();
                let (writer, writer_guard) = tracing_appender::non_blocking(writer);
                let writer = fmt::Layer::default()
                    .with_ansi(false)
                    .with_writer(writer)
                    .event_format(LogEventFormat { mode });
                (writer, writer_guard)
            }
        }
        config::log::Output::FILE => {
            let p = Path::new(&config.output_file);
            let writer = OpenOptions::new().append(true).create(true).open(p)?;
            let (writer, writer_guard) = tracing_appender::non_blocking(writer);
            let writer = fmt::Layer::default()
                .with_ansi(false)
                .with_writer(writer)
                .event_format(LogEventFormat { mode });
            (writer, writer_guard)
        }
    })
}

pub fn setup_logger(config: &config::Log) -> Result<()> {
    let filter = match config.level.unwrap() {
        config::log::Level::TRACE => LevelFilter::TRACE,
        config::log::Level::DEBUG => LevelFilter::DEBUG,
        config::log::Level::INFO => LevelFilter::INFO,
        config::log::Level::WARN => LevelFilter::WARN,
        config::log::Level::ERROR => LevelFilter::ERROR,
        config::log::Level::NONE => return Ok(()),
    };
    let (writer, writer_guard) = get_writer(config)?;
    let mut h = HANDLE.write().unwrap();
    if let Some(h) = h.as_mut() {
        h.reload(filter, writer, writer_guard)?;
    } else {
        let (filter, filter_handle) = reload::Layer::new(filter);
        let (writer, writer_handle) = reload::Layer::new(writer);
        let leaf_filter = filter_fn(|metadata| metadata.target().starts_with("leaf"));
        tracing_subscriber::registry()
            .with(filter)
            .with(writer.with_filter(leaf_filter))
            .init();
        *h = Some(HandleController::new(
            filter_handle,
            writer_handle,
            writer_guard,
        ));
    }
    Ok(())
}
