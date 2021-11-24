use rand::{thread_rng, Rng};
use rand::rngs::OsRng;
use voprf::{NonVerifiableClient, NonVerifiableClientBlindResult, NonVerifiableServer, NonVerifiableServerEvaluateResult, BlindedElement, EvaluationElement};
use curve25519_dalek::digest::generic_array::GenericArray;

type Group = curve25519_dalek::ristretto::RistrettoPoint;
type Hash = sha2::Sha512;

pub fn generate_secret() -> [u8; 32] {
    thread_rng().gen()
}

pub fn client_init(password: &[u8]) -> NonVerifiableClientBlindResult<Group, Hash> {
    let mut client_rng = OsRng;

    NonVerifiableClient::<Group, Hash>::blind(
        password.to_vec(),
        &mut client_rng,
    ).expect("Unable to construct client")
}

pub fn server_evaluate(client_blind_result: BlindedElement<Group, Hash>, secret_salt: [u8; 32]) -> EvaluationElement<Group, Hash> {
    let server = NonVerifiableServer::<Group, Hash>::new_with_key(&secret_salt)
        .expect("Unable to construct server");

    server.evaluate(
        client_blind_result,
        None,
    ).expect("Unable to perform server evaluate").message
}

pub fn client_finish(client_blind_result: NonVerifiableClientBlindResult<Group, Hash>, server_evaluate_result: EvaluationElement<Group, Hash>) -> Vec<u8> {
    client_blind_result.state.finalize(
        server_evaluate_result,
        None,
    ).expect("Unable to perform client finalization").to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn try_oprf_fn() {
        let password = b"input";

        // Client
        let client_blind_result = client_init(password);
        println!("VOPRF blind result: {:?}", client_blind_result.message.serialize());

        // Server
        let secret_salt = generate_secret();
        let server_evaluate_result = server_evaluate(client_blind_result.message.clone(), secret_salt);
        println!("VOPRF secret salt: {:?}", secret_salt);

        // Client
        let client_finalize_result = client_finish(client_blind_result, server_evaluate_result);
        println!("VOPRF output: {:?}", client_finalize_result.to_vec());


        println!();
        // Retry


        // Client
        let client_blind_result2 = client_init(password);
        println!("VOPRF blind result: {:?}", client_blind_result2.message.serialize());

        // Server
        let server_evaluate_result2 = server_evaluate(client_blind_result2.message.clone(), secret_salt);
        println!("VOPRF secret salt: {:?}", secret_salt);

        // Client
        let client_finalize_result2 = client_finish(client_blind_result2, server_evaluate_result2);
        println!("VOPRF output: {:?}", client_finalize_result2.to_vec());

        assert_eq!(client_finalize_result, client_finalize_result2);
    }
}