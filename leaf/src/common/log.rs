pub fn setup_logger(loglevel: log::LevelFilter) -> fern::Dispatch {
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(
                #[cfg(any(target_os = "ios", target_os = "android"))]
                {
                    format_args!(
                        "[{date}][{level}] {message}",
                        date = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        level = record.level(),
                        message = message,
                    )
                },
                #[cfg(not(any(target_os = "ios", target_os = "android")))]
                {
                    use fern::colors::{Color, ColoredLevelConfig};
                    let colors_line = ColoredLevelConfig::new()
                        .error(Color::Red)
                        .warn(Color::Yellow)
                        .info(Color::White)
                        .debug(Color::White)
                        .trace(Color::BrightBlack);

                    let colors_level = colors_line.clone().info(Color::Green);
                    format_args!(
                        // "{color_line}[{date}][{level}{color_line}][{target}] {message}\x1B[0m",
                        "{color_line}[{date}][{level}{color_line}] {message}\x1B[0m",
                        color_line = format_args!(
                            "\x1B[{}m",
                            colors_line.get_color(&record.level()).to_fg_str()
                        ),
                        date = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        // target = record.target(),
                        level = colors_level.color(record.level()),
                        message = message,
                    )
                },
            )
        })
        .level(log::LevelFilter::Warn)
        .level_for("leaf", loglevel)
}

pub fn apply_logger(dispatch: fern::Dispatch) {
    dispatch.apply().expect("setup logger failed");
}
