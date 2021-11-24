use voprf::{NonVerifiableServer, NonVerifiableClient, NonVerifiableClientBlindResult, BlindedElement};
use rand::{rngs::OsRng, RngCore};
use crate::oprf;
use std::borrow::BorrowMut;
use crate::group;

type Group = curve25519_dalek::ristretto::RistrettoPoint;
type Hash = sha2::Sha512;

type CurvePoint = curve25519_dalek::montgomery::MontgomeryPoint;
type CurveScalar = curve25519_dalek::scalar::Scalar;

type OprfValue = String;
type FileEntry = String;
type Ciphertext = String;


pub struct RegisterRequest {
    pub uid: String,
    pub oprf_client_blind_result: Vec<u8>, // oprf init
}

pub struct RegisterResponse {
    pub B: CurvePoint, // curve point
    pub oprf_server_evalute_result: Vec<u8>, // oprf init
}

pub struct RegisterFinish {
    pub encrypted_envelope: Ciphertext, // Encrypted envelope
    pub A: CurvePoint // curve point
}

pub struct Envelope {
    pub a: CurveScalar,
    pub B: CurvePoint,
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

pub fn client_register_finish(register_response: RegisterResponse, oprf_client_state: NonVerifiableClient<Group, Hash>) -> RegisterFinish {
    // Generate asymmetric key
    let (a, A) = group::generate_keys();

    // Compute OPRF output
    let rw = oprf::client_finish(oprf_client_state, register_response.oprf_server_evalute_result);

    // Encrypt (a, B) with rw
    let envelope = Envelope {
        a,
        B: register_response.B,
    };

    let ciphertext = envelope;

    // Return ciphertext
    RegisterFinish {
        encrypted_envelope: ciphertext,
        A,
    }
}

// Sends e and A (RegisterFinish)

pub fn server_register_finish(register_finish: RegisterFinish, b: CurveScalar, salt: [u8; 32]) -> FileEntry {
    // store (e, b, A, salt)
    unimplemented!()
}