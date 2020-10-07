use std::{
    ffi,
    io::{self, Write},
    ptr,
};

use bytes::BytesMut;
use log::{Level, Metadata, Record};

use super::ios::{asl_log, ASL_LEVEL_NOTICE};

fn log_out(data: &[u8]) {
    unsafe {
        let s = match ffi::CString::new(data) {
            Ok(s) => s,
            Err(_) => return,
        };
        asl_log(
            ptr::null_mut(),
            ptr::null_mut(),
            ASL_LEVEL_NOTICE as i32,
            // ffi::CString::new("%s").unwrap().as_c_str().as_ptr(),
            s.as_c_str().as_ptr(),
        )
    };
}

pub struct ConsoleLogger;

impl log::Log for ConsoleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            log_out(
                format!(
                    "[{}] [{}] {}",
                    record.level(),
                    record.target(),
                    record.args()
                )
                .as_bytes(),
            )
        }
    }

    fn flush(&self) {}
}

pub struct ConsoleWriter(pub BytesMut);

unsafe impl Send for ConsoleWriter {}

impl Write for ConsoleWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        if let Some(i) = memchr::memchr(b'\n', &self.0) {
            log_out(&self.0[..i]);
            let _ = self.0.split_to(i + 1);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
