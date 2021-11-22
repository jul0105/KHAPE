use crate::try_dalek::*;
use crate::khape::{client_register_start, server_register_start, client_register_finish, server_register_finish};

mod try_dalek;
mod khape;

fn main() {
    println!("Start");

    try_dalek_ecc();
    try_dalek_ecc2();
    try_triple_dh();
    println!("Finished");
}



fn test_khape() {
    client_register_start();
    server_register_start();
    client_register_finish();
    server_register_finish();
}