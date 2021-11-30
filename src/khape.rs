use serde::{Deserialize, Serialize};

use crate::encryption::{EncryptedEnvelope, Envelope};
use crate::group;
use crate::oprf;
use crate::group::generate_keys;
use crate::tripledh;
use crate::prf;
use std::convert::TryFrom;

pub(crate) type Group = curve25519_dalek::ristretto::RistrettoPoint;
pub(crate) type Hash = sha3::Sha3_256;
pub(crate) type RawPublicKey = curve25519_dalek::montgomery::MontgomeryPoint;
pub(crate) type SharedKey = curve25519_dalek::montgomery::MontgomeryPoint;
pub(crate) type PublicKey = curve25519_dalek::field::FieldElement;
pub(crate) type PrivateKey = curve25519_dalek::scalar::Scalar;


pub type OprfClientState = voprf::NonVerifiableClient<Group, Hash>;




//////////////////////////////////////////////
//                  LOGIN                   //
//////////////////////////////////////////////

// Serialize (send)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterRequest {
    uid: String,
    oprf_client_blind_result: Vec<u8>,
}

// Serialize (send)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterResponse {
    B: PublicKey,
    oprf_server_evalute_result: Vec<u8>,
}

// Serialize (send)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterFinish {
    encrypted_envelope: EncryptedEnvelope,
    A: PublicKey
}

// Serialize (store)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileEntry {
    pub e: EncryptedEnvelope,
    pub b: PrivateKey,
    pub A: PublicKey,
    pub secret_salt: [u8; 32],
}

// Serialize (store)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PreRegisterSecrets {
    private_key: PrivateKey,
    secret_salt: [u8; 32]
}

/// Return RegisterRequest and oprf_client_state
pub fn client_register_start(uid: &str, pw: &[u8]) -> (RegisterRequest, OprfClientState) {
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
pub fn server_register_start(register_request: RegisterRequest) -> (RegisterResponse, PreRegisterSecrets) {
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
    },
    PreRegisterSecrets {
        private_key: b,
        secret_salt
    })
}

// Response B and h2 (RegisterResponse)

/// Return RegisterFinish (ciphertext, A)
pub fn client_register_finish(register_response: RegisterResponse, oprf_client_state: OprfClientState) -> RegisterFinish {
    // Generate asymmetric key
    let (a, A) = group::generate_keys();

    // Compute OPRF output
    let rw = oprf::client_finish(oprf_client_state, register_response.oprf_server_evalute_result);

    // TODO slow hash ?

    // Encrypt (a, B) with rw
    let envelope = Envelope {
        a,
        B: register_response.B
    };
    let encrypted_envelope = envelope.encrypt(<[u8; 32]>::try_from(rw).unwrap());

    // Return ciphertext
    RegisterFinish {
        encrypted_envelope,
        A,
    }
}

// Sends e and A (RegisterFinish)

pub fn server_register_finish(register_finish: RegisterFinish, pre_register_secrets: PreRegisterSecrets) -> FileEntry {
    // Store (e, b, A, salt)
    FileEntry {
        e: register_finish.encrypted_envelope,
        b: pre_register_secrets.private_key,
        A: register_finish.A,
        secret_salt: pre_register_secrets.secret_salt
    }
}




//////////////////////////////////////////////
//                 REGISTER                 //
//////////////////////////////////////////////

type PreKey = [u8; 32];
pub type OutputKey = Option<[u8; 32]>;
type VerifyTag = OutputKey;
type FileStorage = Vec<FileEntry>;


pub struct EphemeralKeys {
    private: PrivateKey,
    public: PublicKey,
}

/// Return AuthRequest (uid and oprf_client_blind_result) and oprf_client_state
pub fn client_auth_start(uid: &str, pw: &[u8]) -> (AuthRequest, OprfClientState) { // TODO similar to client_register_start
    // Compute OPRF initialization
    let (client_state, client_blind_result) = oprf::client_init(pw);

    // Add OPRF client blind and uid to a struct
    (AuthRequest {
        uid: String::from(uid),
        oprf_client_blind_result: client_blind_result,
    }, client_state)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthRequest {
    uid: String,
    oprf_client_blind_result: Vec<u8>,
}

/// Return AuthResponse (e, Y, oprf_server_evalute_result) and EphemeralKeys (server Y and y)
pub fn server_auth_start(auth_request: AuthRequest, file_entry: &FileEntry) -> (AuthResponse, EphemeralKeys) {
    // Generate asymmetric key
    let (y, Y) = generate_keys();

    // Retrieve (e, salt) from file
    let secret_salt = file_entry.secret_salt.clone();
    let encrypted_envelope = file_entry.e.clone();

    // Compute OPRF server evaluate
    let server_evaluate_result = oprf::server_evaluate(auth_request.oprf_client_blind_result, secret_salt);

    // Return e, Y, y, h2 % TODO how to store y ? Store in file[uid] (remove it on server_auth_finish) OR use a session_file[sid] <- (y)
    (AuthResponse {
        encrypted_envelope,
        Y,
        oprf_server_evalute_result: server_evaluate_result,
    },
    EphemeralKeys {
        private: y,
        public: Y,
    })
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthResponse {
    encrypted_envelope: EncryptedEnvelope,
    Y: PublicKey,
    oprf_server_evalute_result: Vec<u8>,
}

/// Return AuthVerifyRequest (t1 and X) and PreKey (k1)
pub fn client_auth_ke(auth_response: AuthResponse, oprf_client_state: OprfClientState) -> (AuthVerifyRequest, PreKey) {
    // Generate asymmetric key
    let (x, X) = generate_keys();

    // Compute OPRF output
    let rw = oprf::client_finish(oprf_client_state, auth_response.oprf_server_evalute_result);

    // TODO slow hash

    // Decrypt (a, B) with rw
    let envelope = auth_response.encrypted_envelope.decrypt(<[u8; 32]>::try_from(rw).unwrap());

    // Compute KeyHidingAKE
    let k1 = tripledh::compute_client(envelope.B, auth_response.Y, envelope.a, x);

    // Compute tag t1
    let t1 = Some(prf::hmac(&k1, b"1"));

    // Return k1, t1 and X
    (AuthVerifyRequest {
        t1,
        X,
    }, k1)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthVerifyRequest {
    t1: VerifyTag,
    X: PublicKey,
}

/// Return AuthVerifyResponse (t2) and OutputKey (K2)
pub fn server_auth_finish(auth_verify_request: AuthVerifyRequest, ephemeral_keys: EphemeralKeys, file_entry: &FileEntry) -> (AuthVerifyResponse, OutputKey) {
    // Retrieve (b, A) from file
    let b = file_entry.b.clone();
    let A = file_entry.A.clone();

    // Compute KeyHidingAKE
    let k2 = tripledh::compute_server(A, auth_verify_request.X, b, ephemeral_keys.private);

    // Verify tag t1 and compute tag t2 and output key
    let (t2, K2) = match auth_verify_request.t1 == Some(prf::hmac(&k2, b"1")) { // TODO ok if none ?
        true => (
            Some(prf::hmac(&k2, b"2")),
            Some(prf::hmac(&k2, b"0"))
        ),
        false => (None, None),
    };

    // Return K2, t2 % TODO what to do with K2 (session key) ? Store in db ? Expiration ? use a session_file[sid] <- K
    (AuthVerifyResponse {
        t2,
    }, K2)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthVerifyResponse {
    t2: VerifyTag,
}

/// Return OutputKey (K1)
pub fn client_auth_finish(auth_verify_response: AuthVerifyResponse, k1: PreKey) -> OutputKey {
    // Verify tag t2 and compute output key
    match auth_verify_response.t2 == Some(prf::hmac(&k1, b"2")) { // TODO ok if none ?
        true => Some(prf::hmac(&k1, b"0")),
        false => None,
    }
}




//////////////////////////////////////////////
//                   TEST                   //
//////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register() {
        let uid = "1234";
        let password = b"test";
        let (register_request, oprf_client_state) = client_register_start(uid, password);

        println!("Sending register request : {:?}", register_request);

        let (register_response, pre_register_secrets) = server_register_start(register_request);

        println!("Sending register response : {:?}", register_response);

        let register_finish = client_register_finish(register_response, oprf_client_state);

        println!("Sending register finish : {:?}", register_finish);

        let file_entry = server_register_finish(register_finish, pre_register_secrets);
    }

    #[test]
    fn test_register_with_serialization() {
        let uid = "1234";
        let password = b"test";


        let (register_request, oprf_client_state) = client_register_start(uid, password);

        let register_request_serialized = serde_json::to_string(&register_request).unwrap();
        println!("Sending register request : {:?}", register_request_serialized);
        let register_request_deserialized: RegisterRequest = serde_json::from_str(&register_request_serialized).unwrap();

        let (register_response, pre_register_secrets) = server_register_start(register_request_deserialized);

        let register_response_serialized = serde_json::to_string(&register_response).unwrap();
        println!("Sending register response : {:?}", register_response_serialized);
        let register_response_deserialized: RegisterResponse = serde_json::from_str(&register_response_serialized).unwrap();

        let register_finish = client_register_finish(register_response_deserialized, oprf_client_state);

        let register_finish_serialized = serde_json::to_string(&register_finish).unwrap();
        println!("Sending register finish : {:?}", register_finish_serialized);
        let register_finish_deserialized: RegisterFinish = serde_json::from_str(&register_finish_serialized).unwrap();

        let file_entry = server_register_finish(register_finish_deserialized, pre_register_secrets);
    }

    fn register(uid: &str, password: &[u8]) -> FileEntry {
        let (register_request, oprf_client_state) = client_register_start(uid, password);
        let (register_response, pre_register_secrets) = server_register_start(register_request);
        let register_finish = client_register_finish(register_response, oprf_client_state);
        server_register_finish(register_finish, pre_register_secrets)
    }

    #[test]
    fn test_auth() {
        let uid = "1234";
        let password = b"test";
        let file_entry = register(uid, password);

        let (auth_request, oprf_client_state) = client_auth_start(uid, password);
        let (auth_response, server_ephemeral_keys) = server_auth_start(auth_request, &file_entry);
        let (auth_verify_request, k1) = client_auth_ke(auth_response, oprf_client_state);
        let (auth_verify_response, K2) = server_auth_finish(auth_verify_request, server_ephemeral_keys, &file_entry);
        let K1 = client_auth_finish(auth_verify_response, k1);

        println!("K1 : {:?}", K1);
        println!("K2 : {:?}", K2);

        assert!(K1.is_some());
        assert_eq!(K1, K2);
    }

    fn auth(uid: &str, password: &[u8], file_entry: FileEntry) -> (OutputKey, OutputKey) {
        let (auth_request, oprf_client_state) = client_auth_start(uid, password);
        let (auth_response, server_ephemeral_keys) = server_auth_start(auth_request, &file_entry);
        let (auth_verify_request, k1) = client_auth_ke(auth_response, oprf_client_state);
        let (auth_verify_response, K2) = server_auth_finish(auth_verify_request, server_ephemeral_keys, &file_entry);
        let K1 = client_auth_finish(auth_verify_response, k1);
        (K1, K2)
    }

    #[test]
    fn test_auth_same_password() {
        let uid = "1234";
        let password = b"test";

        let file_entry = register(uid, password);
        let (K1, K2) = auth(uid, password, file_entry);

        assert!(K1.is_some());
        assert_eq!(K1, K2);
    }

    #[test]
    fn test_auth_different_password() {
        let uid = "1234";
        let password_register = b"test";
        let password_auth = b"testt";

        let file_entry = register(uid, password_register);
        let (K1, K2) = auth(uid, password_auth, file_entry);

        assert!(K1.is_none());
        assert!(K2.is_none());
        assert_eq!(K1, K2);
    }
}