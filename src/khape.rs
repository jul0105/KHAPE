use std::borrow::BorrowMut;

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use voprf::{BlindedElement, NonVerifiableClient, NonVerifiableClientBlindResult, NonVerifiableServer};

use crate::encryption::{EncryptedEnvelope, Envelope};
use crate::group;
use crate::oprf;

type Group = curve25519_dalek::ristretto::RistrettoPoint;
type Hash = sha2::Sha512;

pub type CurvePoint = curve25519_dalek::montgomery::MontgomeryPoint;
pub type CurveScalar = curve25519_dalek::scalar::Scalar;


// Serialize (send)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterRequest {
    pub uid: String,
    pub oprf_client_blind_result: Vec<u8>,
}

// Serialize (send)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterResponse {
    pub B: CurvePoint,
    pub oprf_server_evalute_result: Vec<u8>,
}

// Serialize (send)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterFinish {
    pub encrypted_envelope: EncryptedEnvelope,
    pub A: CurvePoint
}

// Serialize (store)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileEntry {
    pub e: EncryptedEnvelope,
    pub b: CurveScalar,
    pub A: CurvePoint,
    pub secret_salt: [u8; 32],
}

/// Return RegisterRequest and oprf_client_state
pub fn client_register_start(uid: &str, pw: &[u8]) -> (RegisterRequest, NonVerifiableClient<Group, Hash>) {
    // Compute OPRF initialization
    let (client_state, client_blind_result) = oprf::client_init(pw);

    // Add OPRF client blind and uid to a struct
    (RegisterRequest {
        uid: String::from(uid),
        oprf_client_blind_result: client_blind_result,
    }, client_state)
}

// Sends uid and h1 (RegisterRequest)

/// Return RegisterResponse (B and oprf_server_evaluate_result), b and secret_salt
pub fn server_register_start(register_request: RegisterRequest) -> (RegisterResponse, CurveScalar, [u8; 32]) {
    // Generate asymmetric key
    let (b, B) = group::generate_keys();

    // Generate OPRF salt
    let secret_salt = oprf::generate_secret();

    // Compute OPRF server evaluate
    let server_evaluate_result = oprf::server_evaluate(register_request.oprf_client_blind_result, secret_salt);

    // Return B and h2 % TODO how to store salt and b (secret) ? Pre - store b and salt in file[uid] (remove it on server_register_finish) OR use a session_file[sid] < - (b, salt)
    (RegisterResponse {
        B,
        oprf_server_evalute_result: server_evaluate_result,
    }, b, secret_salt)
}

// Response B and h2 (RegisterResponse)

/// Return RegisterFinish (ciphertext, A)
pub fn client_register_finish(register_response: RegisterResponse, oprf_client_state: NonVerifiableClient<Group, Hash>) -> RegisterFinish {
    // Generate asymmetric key
    let (a, A) = group::generate_keys();

    // Compute OPRF output
    let rw = oprf::client_finish(oprf_client_state, register_response.oprf_server_evalute_result);

    // Encrypt (a, B) with rw
    let envelope = Envelope {
        a,
        B: register_response.B
    };
    let encrypted_envelope = envelope.encrypt();

    // Return ciphertext
    RegisterFinish {
        encrypted_envelope,
        A,
    }
}

// Sends e and A (RegisterFinish)

pub fn server_register_finish(register_finish: RegisterFinish, b: CurveScalar, secret_salt: [u8; 32]) -> FileEntry {
    // Store (e, b, A, salt)
    FileEntry {
        e: register_finish.encrypted_envelope,
        b,
        A: register_finish.A,
        secret_salt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register() {
        let uid = "1234";
        let password = b"test";
        let (register_request, oprf_client_state) = client_register_start(uid, password);

        println!("Sending register request : {:?}", register_request);

        let (register_response, b, secret_salt) = server_register_start(register_request);

        println!("Sending register response : {:?}", register_response);

        let register_finish = client_register_finish(register_response, oprf_client_state);

        println!("Sending register finish : {:?}", register_finish);

        let file_entry = server_register_finish(register_finish, b, secret_salt);
    }

    #[test]
    fn register_with_serialization() {
        let uid = "1234";
        let password = b"test";


        let (register_request, oprf_client_state) = client_register_start(uid, password);

        let register_request_serialized = serde_json::to_string(&register_request).unwrap();
        println!("Sending register request : {:?}", register_request_serialized);
        let register_request_deserialized: RegisterRequest = serde_json::from_str(&register_request_serialized).unwrap();

        let (register_response, b, secret_salt) = server_register_start(register_request_deserialized);

        let register_response_serialized = serde_json::to_string(&register_response).unwrap();
        println!("Sending register response : {:?}", register_response_serialized);
        let register_response_deserialized: RegisterResponse = serde_json::from_str(&register_response_serialized).unwrap();

        let register_finish = client_register_finish(register_response_deserialized, oprf_client_state);

        let register_finish_serialized = serde_json::to_string(&register_finish).unwrap();
        println!("Sending register finish : {:?}", register_finish_serialized);
        let register_finish_deserialized: RegisterFinish = serde_json::from_str(&register_finish_serialized).unwrap();

        let file_entry = server_register_finish(register_finish_deserialized, b, secret_salt);
    }
}