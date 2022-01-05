//! Protocol messages structure that are transmitted between the client and the server

use core::option::Option;
use serde::{Deserialize, Serialize};

use crate::alias::{PrivateKey, PublicKey, VerifyTag, OPRF_SALT_SIZE};
use crate::encryption::EncryptedEnvelope;

/////////////////////////////////////////
//          Protocol messages          //
/////////////////////////////////////////

/// Client generated registration request (#1 reg. message)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterRequest {
    pub uid: String,
    pub(crate) oprf_client_blind_result: Option<Vec<u8>>,
}

/// Server generated registration response (#2 reg. message)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterResponse {
    pub(crate) pub_b: PublicKey,
    pub(crate) oprf_server_evalute_result: Option<Vec<u8>>,
}

/// Client generated registration finish (#3 reg. message)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterFinish {
    pub uid: String,
    pub(crate) encrypted_envelope: EncryptedEnvelope,
    pub(crate) pub_a: PublicKey
}


/// Client generated authentication request (#1 auth. message)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthRequest {
    pub uid: String,
    pub(crate) oprf_client_blind_result: Option<Vec<u8>>,
}

/// Server generated authentication response (#2 auth. message)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthResponse {
    pub(crate) encrypted_envelope: EncryptedEnvelope,
    pub(crate) pub_y: PublicKey,
    pub(crate) oprf_server_evalute_result: Option<Vec<u8>>,
}

/// Client generated authentication verification request (#3 auth. message)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthVerifyRequest {
    pub uid: String,
    pub(crate) client_verify_tag: VerifyTag,
    pub(crate) pub_x: PublicKey,
}

/// Server generated authentication verification response (#4 auth. message)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthVerifyResponse {
    pub(crate) server_verify_tag: Option<VerifyTag>,
}


/////////////////////////////////////
//          Server struct          //
/////////////////////////////////////

/// User's data that are stored on the server
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileEntry {
    pub encrypted_envelope: EncryptedEnvelope,
    pub priv_b: PrivateKey,
    pub pub_a: PublicKey,
    pub secret_salt: Option<[u8; OPRF_SALT_SIZE]>,
}

/// Server's secrets that are temporary stored on the server during registration process
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PreRegisterSecrets {
    pub(crate) private_key: PrivateKey,
    pub(crate) secret_salt: Option<[u8; OPRF_SALT_SIZE]>
}

/// Server's key that are temporary stored on the server during authentication process
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EphemeralKeys {
    pub(crate) private: PrivateKey,
    pub(crate) public: PublicKey,
}
