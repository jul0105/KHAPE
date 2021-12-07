use core::option::Option;
use serde::{Deserialize, Serialize};

use crate::alias::{PrivateKey, PublicKey, VerifyTag};
use crate::encryption::EncryptedEnvelope;

/////////////////////////////////////////
//          Protocol messages          //
/////////////////////////////////////////

// Serialize (send)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterRequest {
    pub uid: String,
    pub(crate) oprf_client_blind_result: Option<Vec<u8>>,
}

// Serialize (send)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterResponse {
    pub(crate) pub_b: PublicKey,
    pub(crate) oprf_server_evalute_result: Option<Vec<u8>>,
}

// Serialize (send)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterFinish {
    pub uid: String,
    pub(crate) encrypted_envelope: EncryptedEnvelope,
    pub(crate) pub_a: PublicKey
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthRequest {
    pub uid: String,
    // pub sid: String, // TODO sid
    pub(crate) oprf_client_blind_result: Option<Vec<u8>>,
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthResponse {
    pub(crate) encrypted_envelope: EncryptedEnvelope,
    pub(crate) pub_y: PublicKey,
    pub(crate) oprf_server_evalute_result: Option<Vec<u8>>,
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthVerifyRequest {
    pub uid: String,
    // pub sid: String, // TODO sid
    pub(crate) client_verify_tag: VerifyTag,
    pub(crate) pub_x: PublicKey,
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthVerifyResponse {
    pub(crate) server_verify_tag: Option<VerifyTag>,
}


/////////////////////////////////////
//          Server struct          //
/////////////////////////////////////

// Serialize (store)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileEntry {
    pub encrypted_envelope: EncryptedEnvelope,
    pub priv_b: PrivateKey,
    pub pub_a: PublicKey,
    pub secret_salt: Option<[u8; 32]>,
}

// Serialize (store)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PreRegisterSecrets {
    pub(crate) private_key: PrivateKey,
    pub(crate) secret_salt: Option<[u8; 32]>
}

pub struct EphemeralKeys {
    pub(crate) private: PrivateKey,
    pub(crate) public: PublicKey,
}
