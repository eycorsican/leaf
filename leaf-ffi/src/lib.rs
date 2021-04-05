use std::{ffi::CStr, os::raw::c_char};

// TODO Return meaningful error codes.
#[no_mangle]
pub extern "C" fn run_leaf(config_path: *const c_char) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    if let Ok(config) = unsafe { CStr::from_ptr(config_path).to_str() }
        .map_err(Into::into)
        .and_then(leaf::config::from_file)
    {
        let runners = match leaf::util::prepare(config) {
            Ok(v) => v,
            Err(e) => {
                println!("prepare failed: {}", e);
                return;
            }
        };
        rt.block_on(futures::future::join_all(runners));
    } else {
        println!("invalid config path or config file");
        return;
    }
}
