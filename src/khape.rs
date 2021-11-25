use std::borrow::BorrowMut;

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use voprf::{BlindedElement, NonVerifiableClient, NonVerifiableClientBlindResult, NonVerifiableServer};

use crate::encryption::{EncryptedEnvelope, Envelope};
use crate::group;
use crate::oprf;

pub type Group = curve25519_dalek::ristretto::RistrettoPoint;
pub type Hash = sha3::Sha3_256;
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




//////////////////////////////////////////////
//                 REGISTER                 //
//////////////////////////////////////////////

type VerifyTag = String;
type PreKey = String;
type OutputKey = String;
type FileStorage = Vec<FileEntry>;


pub struct EphemeralKeys {
    private: CurveScalar,
    public: CurvePoint,
}

/// Return AuthRequest (uid and oprf_client_blind_result)
pub fn client_auth_start(uid: &str, pw: &[u8]) -> AuthRequest {
    // similar to client_register_start
    // compute OPRF initialization
    // add OPRF h1 and uid to a struct
    // return struct
    unimplemented!()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthRequest {
    pub uid: String,
    pub oprf_client_blind_result: Vec<u8>,
}

/// Return AuthResponse (e, Y, oprf_server_evalute_result) and EphemeralKeys (server Y and y)
pub fn server_auth_start(auth_request: AuthRequest, file: FileStorage) -> (AuthResponse, EphemeralKeys) {
    // generate_asymetric_key
    // retrieve (e, salt) from file
    // compute OPRF h2 % TODO ensure that client-side attacker cannot retrieve salt (by inputing anoter user uid)
    // return e, Y, y, h2 % TODO how to store y ? Store in file[uid] (remove it on server_auth_finish) OR use a session_file[sid] <- (y)
    unimplemented!()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthResponse {
    pub encrypted_envelope: EncryptedEnvelope,
    pub Y: CurvePoint,
    pub oprf_server_evalute_result: Vec<u8>,
}

/// Return AuthVerifyRequest (t1 and X) and PreKey (k1)
pub fn client_auth_ke(auth_response: AuthResponse, oprf_client_state: NonVerifiableClient<Group, Hash>) -> (AuthVerifyRequest, VerifyTag) {
    // generate_asymetric_key
    // compute OPRF output
    // decrypt (a, B) with rw
    // compute KeyHidingAKE
    // compute k1 and t1 % TODO sid, C, S ?
    // return k1, t1 and X
    unimplemented!()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthVerifyRequest {
    pub t1: VerifyTag,
    pub X: CurvePoint,
}

/// Return AuthVerifyResponse (t2) and OutputKey (K2)
pub fn server_auth_finish(auth_verify_request: AuthVerifyRequest, ephemeral_keys: EphemeralKeys, file: FileStorage) -> (AuthVerifyResponse, OutputKey) {
    // retrieve (b, A) from file
    // compute KeyHidingAKE
    // compute k2 % TODO sid, C, S ?
    // verify t1
    // compute t2 and K2
    // return K2, t2 % TODO what to do with K2 (session key) ? Store in db ? Expiration ? use a session_file[sid] <- K
    unimplemented!()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthVerifyResponse {
    pub t2: VerifyTag,
}

/// Return OutputKey (K1)
pub fn client_auth_finish(t2: VerifyTag, k1: PreKey) -> OutputKey {
    // verify t2
    // compute K1
    // return K1
    unimplemented!()
}