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

pub fn server_evaluate(client_blind_result: BlindedElement<Group, Hash>) -> EvaluationElement<Group, Hash> {
    let secret_salt = generate_secret();
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