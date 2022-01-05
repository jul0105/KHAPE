use rand::{Rng, thread_rng};
use rand::rngs::OsRng;
use voprf::{BlindedElement, EvaluationElement, NonVerifiableClient, NonVerifiableServer};

use crate::alias::{Group, Hash, OPRF_SALT_SIZE};
use crate::alias::OprfClientState;

#[derive(Clone)]
pub enum ClientState {
    WithOPRF(OprfClientState),
    WithoutOPRF(Vec<u8>),
}


pub(crate) fn generate_secret(use_oprf: bool) -> Option<[u8; OPRF_SALT_SIZE]> {
    if use_oprf {
        Some(thread_rng().gen())
    } else {
        None
    }
}

pub(crate) fn client_init(use_oprf: bool, password: &[u8]) -> (ClientState, Option<Vec<u8>>) {
    if !use_oprf {
        return (ClientState::WithoutOPRF(Vec::from(password)), None);
    }

    let mut client_rng = OsRng;

    let result = NonVerifiableClient::<Group, Hash>::blind(
        password.to_vec(),
        &mut client_rng,
    ).expect("Unable to construct client");

    (ClientState::WithOPRF(result.state), Some(result.message.serialize()))
}

pub(crate) fn server_evaluate(use_oprf: bool, client_blind_result: Option<Vec<u8>>, secret_salt: Option<[u8; OPRF_SALT_SIZE]>) -> Option<Vec<u8>> {
    if !use_oprf {
        return None;
    }

    if client_blind_result.is_none() || secret_salt.is_none() {
        // TODO handle error
    }

    let server = NonVerifiableServer::<Group, Hash>::new_with_key(&secret_salt.unwrap())
        .expect("Unable to construct server");

    Some(server.evaluate(
        BlindedElement::<Group, Hash>::deserialize(&client_blind_result.unwrap()).unwrap(), // TODO unwrap
        None,
    ).expect("Unable to perform server evaluate").message.serialize())
}

pub(crate) fn client_finish(use_oprf: bool, client_state: ClientState, server_evaluate_result: Option<Vec<u8>>) -> Vec<u8> {
    return match client_state {
        ClientState::WithoutOPRF(pw) => pw,
        ClientState::WithOPRF(oprf_client_state) => match use_oprf && server_evaluate_result.is_some() {
            true => oprf_client_state.finalize(
                    EvaluationElement::<Group, Hash>::deserialize(&server_evaluate_result.unwrap()).unwrap(), // TODO unwrap
                    None,
                ).expect("Unable to perform client finalization").to_vec(),
            false => panic!("TO HANDLE"), // TODO handle error
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oprf_turned_on_with_same_password() {
        let password = b"input";
        let use_oprf: bool = true;

        let (oprf_output1, oprf_output2) = oprf_process(password, password, use_oprf);
        assert_eq!(oprf_output1, oprf_output2)
    }

    #[test]
    fn test_oprf_turned_off_with_same_password() {
        let password = b"input";
        let use_oprf: bool = false;

        let (oprf_output1, oprf_output2) = oprf_process(password, password, use_oprf);
        assert_eq!(oprf_output1, oprf_output2)    }

    #[test]
    fn test_oprf_turned_on_with_different_password() {
        let password1 = b"input";
        let password2 = b"awdwdaw";
        let use_oprf: bool = true;

        let (oprf_output1, oprf_output2) = oprf_process(password1, password2, use_oprf);
        assert_ne!(oprf_output1, oprf_output2)    }

    #[test]
    fn test_oprf_turned_off_with_different_password() {
        let password1 = b"input";
        let password2 = b"awdwdaw";
        let use_oprf: bool = false;

        let (oprf_output1, oprf_output2) = oprf_process(password1, password2, use_oprf);
        assert_ne!(oprf_output1, oprf_output2)    }

    fn oprf_process(password1: &[u8], password2: &[u8], use_oprf: bool) -> (Vec<u8>, Vec<u8>) {
        // Client
        let (client_state, client_blind_result) = client_init(use_oprf, password1);
        println!("VOPRF blind result: {:?}", client_blind_result);

        // Server
        let secret_salt = generate_secret(use_oprf);
        let server_evaluate_result = server_evaluate(use_oprf, client_blind_result, secret_salt);
        println!("VOPRF secret salt: {:?}", secret_salt);

        // Client
        let client_finalize_result = client_finish(use_oprf, client_state, server_evaluate_result);
        println!("VOPRF output: {:?}", client_finalize_result);


        println!();
        // Retry


        // Client
        let (client_state2, client_blind_result2) = client_init(use_oprf, password2);
        println!("VOPRF blind result: {:?}", client_blind_result2);

        // Server
        let server_evaluate_result2 = server_evaluate(use_oprf, client_blind_result2, secret_salt);
        println!("VOPRF secret salt: {:?}", secret_salt);

        // Client
        let client_finalize_result2 = client_finish(use_oprf, client_state2, server_evaluate_result2);
        println!("VOPRF output: {:?}", client_finalize_result2);

        (client_finalize_result, client_finalize_result2)
    }
}