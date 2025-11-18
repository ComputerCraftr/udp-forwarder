#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        ::std::println!("[INFO] {}", ::std::format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        ::std::eprintln!("[WARN] {}", ::std::format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        ::std::eprintln!("[ERROR] {}", ::std::format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! log_debug {
    ($enabled:expr, $($arg:tt)*) => {
        if $enabled {
            ::std::eprintln!("[DEBUG] {}", ::std::format_args!($($arg)*));
        }
    };
}
