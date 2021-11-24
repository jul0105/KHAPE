use voprf::{NonVerifiableServer, NonVerifiableClient};
use rand::{rngs::OsRng, RngCore};
use crate::oprf;

type Group = curve25519_dalek::ristretto::RistrettoPoint;
type Hash = sha2::Sha512;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn try_oprf_fn() {
        let password = b"input";

        // Client
        let client_blind_result = oprf::client_init(password);
        println!("VOPRF blind result: {:?}", client_blind_result.message.serialize());

        // Server
        let secret_salt = oprf::generate_secret();
        let server_evaluate_result = oprf::server_evaluate(client_blind_result.message.clone(), secret_salt);
        println!("VOPRF secret salt: {:?}", secret_salt);

        // Client
        let client_finalize_result = oprf::client_finish(client_blind_result, server_evaluate_result);
        println!("VOPRF output: {:?}", client_finalize_result.to_vec());


        println!();
        // Retry


        // Client
        let client_blind_result2 = oprf::client_init(password);
        println!("VOPRF blind result: {:?}", client_blind_result2.message.serialize());

        // Server
        let server_evaluate_result2 = oprf::server_evaluate(client_blind_result2.message.clone(), secret_salt);
        println!("VOPRF secret salt: {:?}", secret_salt);

        // Client
        let client_finalize_result2 = oprf::client_finish(client_blind_result2, server_evaluate_result2);
        println!("VOPRF output: {:?}", client_finalize_result2.to_vec());

        assert_eq!(client_finalize_result, client_finalize_result2);
    }
}