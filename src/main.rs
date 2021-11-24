use crate::try_dalek::*;
use crate::oprf::*;
use crate::khape::{client_register_start, server_register_start, client_register_finish, server_register_finish};

mod try_dalek;
mod khape;
mod oprf;
mod group;
mod tripledh;

fn main() {
    println!("Start 3DH");
    try_dalek_ecc();
    try_dalek_ecc2();
    try_triple_dh();
    println!("Finished 3DH");
}



// fn test_khape() {
//     client_register_start();
//     server_register_start();
//     client_register_finish();
//     server_register_finish();
// }