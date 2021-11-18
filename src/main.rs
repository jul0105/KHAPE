use crate::try_dalek::*;

mod try_dalek;

fn main() {
    println!("Start");

    try_dalek_ecc();
    try_dalek_ecc2();
    try_triple_dh();
    println!("Finished");
}