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

#[macro_export]
macro_rules! log_info_dir {
    ($worker:expr, $c2u:expr, $($arg:tt)*) => {
        ::std::println!(
            "[INFO][worker {}][{}] {}",
            $worker,
            if $c2u { "c2u" } else { "u2c" },
            ::std::format_args!($($arg)*)
        );
    };
}

#[macro_export]
macro_rules! log_warn_dir {
    ($worker:expr, $c2u:expr, $($arg:tt)*) => {
        ::std::eprintln!(
            "[WARN][worker {}][{}] {}",
            $worker,
            if $c2u { "c2u" } else { "u2c" },
            ::std::format_args!($($arg)*)
        );
    };
}

#[macro_export]
macro_rules! log_error_dir {
    ($worker:expr, $c2u:expr, $($arg:tt)*) => {
        ::std::eprintln!(
            "[ERROR][worker {}][{}] {}",
            $worker,
            if $c2u { "c2u" } else { "u2c" },
            ::std::format_args!($($arg)*)
        );
    };
}

#[macro_export]
macro_rules! log_debug_dir {
    ($enabled:expr, $worker:expr, $c2u:expr, $($arg:tt)*) => {
        if $enabled {
            ::std::eprintln!(
                "[DEBUG][worker {}][{}] {}",
                $worker,
                if $c2u { "c2u" } else { "u2c" },
                ::std::format_args!($($arg)*)
            );
        }
    };
}
