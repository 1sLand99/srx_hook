#![allow(unsafe_op_in_unsafe_fn)]

mod scenarios;
mod test_ctx;

use srx_hook::set_debug;

fn main() {
    set_debug(true);
    unsafe {
        scenarios::run_all();
    }
    println!("hook_test all scenarios passed");
}
