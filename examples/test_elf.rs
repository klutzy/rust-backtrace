extern crate backtrace;

fn main() {
    // TODO
    if cfg!(windows) { return; }
    backtrace::print_traceback().unwrap();

    println!("ok");
}
