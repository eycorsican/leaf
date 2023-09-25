use std::fs::OpenOptions;
use std::path::Path;
use std::sync::RwLock;

use anyhow::Result;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    filter::LevelFilter, fmt, layer::Layered, prelude::*, registry::Registry, reload,
    reload::Handle,
};

use crate::config;

type FilterHandle = Handle<LevelFilter, Registry>;

type WriterLayer = fmt::Layer<
    Layered<reload::Layer<LevelFilter, Registry>, Registry>,
    tracing_subscriber::fmt::format::DefaultFields,
    tracing_subscriber::fmt::format::Format,
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
    Ok(match config.output.unwrap() {
        config::log::Output::CONSOLE => {
            #[cfg(target_os = "macos")]
            {
                if *crate::option::LOG_CONSOLE_OUT {
                    let writer = crate::mobile::logger::ConsoleWriter::default();
                    let (writer, writer_guard) = tracing_appender::non_blocking(writer);
                    let writer = fmt::Layer::default().with_ansi(false).with_writer(writer);
                    (writer, writer_guard)
                } else {
                    let (writer, writer_guard) = tracing_appender::non_blocking(std::io::stdout());
                    let writer = fmt::Layer::default().with_writer(writer);
                    (writer, writer_guard)
                }
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            {
                let (writer, writer_guard) = tracing_appender::non_blocking(std::io::stdout());
                let writer = fmt::Layer::default().with_writer(writer);
                (writer, writer_guard)
            }
            #[cfg(any(target_os = "ios", target_os = "android"))]
            {
                let writer = crate::mobile::logger::ConsoleWriter::default();
                let (writer, writer_guard) = tracing_appender::non_blocking(writer);
                let writer = fmt::Layer::default().with_ansi(false).with_writer(writer);
                (writer, writer_guard)
            }
        }
        config::log::Output::FILE => {
            let p = Path::new(&config.output_file);
            let writer = OpenOptions::new().append(true).create(true).open(p)?;
            let (writer, writer_guard) = tracing_appender::non_blocking(writer);
            let writer = fmt::Layer::default().with_ansi(false).with_writer(writer);
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
    };
    let (writer, writer_guard) = get_writer(config)?;
    let mut h = HANDLE.write().unwrap();
    if let Some(h) = h.as_mut() {
        h.reload(filter, writer, writer_guard)?;
    } else {
        let (filter, filter_handle) = reload::Layer::new(filter);
        let (writer, writer_handle) = reload::Layer::new(writer);
        tracing_subscriber::registry()
            .with(filter)
            .with(writer)
            .init();
        *h = Some(HandleController::new(
            filter_handle,
            writer_handle,
            writer_guard,
        ));
    }
    Ok(())
}
