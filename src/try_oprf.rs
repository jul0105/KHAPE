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

        // Server
        let secret_salt = oprf::generate_secret();
        let client_blind_message = client_blind_result.message.clone();
        let server_evaluate_result = oprf::server_evaluate(client_blind_message);
        println!("VOPRF secret salt: {:?}", secret_salt);

        // Client
        let client_finalize_result = oprf::client_finish(client_blind_result, server_evaluate_result);

        println!("VOPRF output: {:?}", client_finalize_result.to_vec());

        // Retry


        // Client
        let mut client_rng = OsRng;
        let client_blind_result = NonVerifiableClient::<Group, Hash>::blind(
            password.to_vec(),
            &mut client_rng,
        ).expect("Unable to construct client");

        // Server
        let server2 = NonVerifiableServer::<Group, Hash>::new_with_key(&secret_salt)
            .expect("Unable to construct server");

        let server_evaluate_result = server2.evaluate(
            client_blind_result.message,
            None,
        ).expect("Unable to perform server evaluate");
        println!("VOPRF secret salt: {:?}", secret_salt);

        // Client
        let client_finalize_result2 = client_blind_result.state.finalize(
            server_evaluate_result.message,
            None,
        ).expect("Unable to perform client finalization");

        println!("VOPRF output: {:?}", client_finalize_result2.to_vec());
        assert_eq!(client_finalize_result, client_finalize_result2.to_vec());
    }
}