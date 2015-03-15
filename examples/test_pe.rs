extern crate backtrace;

// temporary one

fn main() {
    if !cfg!(windows) { return; }
    backtrace::pe::doit().unwrap();

    println!("ok");
}
