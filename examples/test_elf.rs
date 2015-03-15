extern crate backtrace;

#[cfg(not(windows))]
fn main() {
    backtrace::print_traceback().unwrap();

    println!("ok");
}

#[cfg(windows)]
fn main() {}
