use rand::{thread_rng, Rng};
use rand::rngs::OsRng;
use voprf::{NonVerifiableClient, NonVerifiableClientBlindResult, NonVerifiableServer, NonVerifiableServerEvaluateResult, BlindedElement, EvaluationElement};
use curve25519_dalek::digest::generic_array::GenericArray;
use crate::khape::{Group, Hash};

pub fn generate_secret() -> [u8; 32] {
    thread_rng().gen()
}

pub fn client_init(password: &[u8]) -> (NonVerifiableClient<Group, Hash>, Vec<u8>) {
    let mut client_rng = OsRng;

    let result = NonVerifiableClient::<Group, Hash>::blind(
        password.to_vec(),
        &mut client_rng,
    ).expect("Unable to construct client");

    (result.state, result.message.serialize())
}

pub fn server_evaluate(client_blind_result: Vec<u8>, secret_salt: [u8; 32]) -> Vec<u8> {
    let server = NonVerifiableServer::<Group, Hash>::new_with_key(&secret_salt)
        .expect("Unable to construct server");

    server.evaluate(
        BlindedElement::<Group, Hash>::deserialize(&client_blind_result).unwrap(), // TODO unwrap
        None,
    ).expect("Unable to perform server evaluate").message.serialize()
}

pub fn client_finish(client_state: NonVerifiableClient<Group, Hash>, server_evaluate_result: Vec<u8>) -> Vec<u8> {
    client_state.finalize(
        EvaluationElement::<Group, Hash>::deserialize(&server_evaluate_result).unwrap(), // TODO unwrap
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
        let (client_state, client_blind_result) = client_init(password);
        println!("VOPRF blind result: {:?}", client_blind_result);

        // Server
        let secret_salt = generate_secret();
        let server_evaluate_result = server_evaluate(client_blind_result, secret_salt);
        println!("VOPRF secret salt: {:?}", secret_salt);

        // Client
        let client_finalize_result = client_finish(client_state, server_evaluate_result);
        println!("VOPRF output: {:?}", client_finalize_result);


        println!();
        // Retry


        // Client
        let (client_state2, client_blind_result2) = client_init(password);
        println!("VOPRF blind result: {:?}", client_blind_result2);

        // Server
        let server_evaluate_result2 = server_evaluate(client_blind_result2, secret_salt);
        println!("VOPRF secret salt: {:?}", secret_salt);

        // Client
        let client_finalize_result2 = client_finish(client_state2, server_evaluate_result2);
        println!("VOPRF output: {:?}", client_finalize_result2);

        assert_eq!(client_finalize_result, client_finalize_result2);
    }
}