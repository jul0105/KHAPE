use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::alias::{OprfClientState, OutputKey, PreKey};
use crate::encryption::{EncryptedEnvelope, Envelope};
use crate::group;
use crate::message::{AuthRequest, AuthResponse, AuthVerifyRequest, AuthVerifyResponse, EphemeralKeys, FileEntry, PreRegisterSecrets, RegisterFinish, RegisterRequest, RegisterResponse};
use crate::oprf;
use crate::oprf::ClientState;
use crate::prf;
use crate::tripledh;
use crate::hash;
use crate::tripledh::KeyExchangeOutput;

#[derive(Clone, Copy)]
pub struct Parameters {
    pub use_oprf: bool,
    pub use_slow_hash: bool,
}

pub struct Client{
    pub parameters: Parameters,
    pub uid: String,
}
pub struct Server{
    pub parameters: Parameters
}

// Client constructor
impl Client {
    pub fn new(parameters: Parameters, uid: String) -> Self {
        Self {
            parameters,
            uid
        }
    }
}

// Server constructor
impl Server {
    pub fn new(parameters: Parameters) -> Self {
        Self {
            parameters
        }
    }
}

// Client register
impl Client {
    /// Return RegisterRequest and oprf_client_state
    pub fn register_start(&self, password: &[u8]) -> (RegisterRequest, ClientState) {
        // Compute OPRF initialization
        let (client_state, client_blind_result) = oprf::client_init(self.parameters.use_oprf, password);

        // Add OPRF client blind and uid to a struct
        (RegisterRequest {
            uid: String::from(&self.uid),
            oprf_client_blind_result: client_blind_result,
        }, client_state)
    }

    /// Return RegisterFinish (ciphertext, A)
    pub fn register_finish(&self, register_response: RegisterResponse, client_state: ClientState) -> RegisterFinish {
        // Generate asymmetric key
        let (priv_a, pub_a) = group::generate_keys();

        // Compute OPRF output
        let oprf_output = oprf::client_finish(self.parameters.use_oprf, client_state, register_response.oprf_server_evalute_result);

        // Compute slow hash
        let hardened_output = match self.parameters.use_slow_hash {
            true => hash::slow_hash(oprf_output.clone()), // TODO slow hash
            false => oprf_output.clone(),
        };

        // Compute encryption key
        let encryption_key = hash::hkdf_envelope_key(oprf_output, hardened_output);

        // Encrypt (a, B) with rw
        let envelope = Envelope {
            priv_a,
            pub_b: register_response.pub_b
        };
        let encrypted_envelope = envelope.encrypt(<[u8; 32]>::try_from(encryption_key).unwrap());

        // Return ciphertext
        RegisterFinish {
            uid: String::from(&self.uid),
            encrypted_envelope,
            pub_a,
        }
    }
}

// Client login
impl Client {
    /// Return AuthRequest (uid and oprf_client_blind_result) and oprf_client_state
    pub fn auth_start(&self, password: &[u8]) -> (AuthRequest, ClientState) { // TODO similar to client_register_start
        // Compute OPRF initialization
        let (client_state, client_blind_result) = oprf::client_init(self.parameters.use_oprf, password);

        // Add OPRF client blind and uid to a struct
        (AuthRequest {
            uid: String::from(&self.uid),
            oprf_client_blind_result: client_blind_result,
        }, client_state)
    }

    /// Return AuthVerifyRequest (t1 and X) and PreKey (k1)
    pub fn auth_ke(&self, auth_response: AuthResponse, client_state: ClientState) -> (AuthVerifyRequest, KeyExchangeOutput) {
        // Generate asymmetric key
        let (priv_x, pub_x) = group::generate_keys();

        // Compute OPRF output
        let oprf_output = oprf::client_finish(self.parameters.use_oprf, client_state, auth_response.oprf_server_evalute_result);

        // Compute slow hash
        let hardened_output = match self.parameters.use_slow_hash {
            true => hash::slow_hash(oprf_output.clone()), // TODO slow hash
            false => oprf_output.clone(),
        };

        // Compute encryption key
        let encryption_key = hash::hkdf_envelope_key(oprf_output, hardened_output);

        // Decrypt (a, B) with rw
        let envelope = auth_response.encrypted_envelope.decrypt(<[u8; 32]>::try_from(encryption_key).unwrap());

        // Compute KeyHidingAKE
        let ke_output = tripledh::compute_client(envelope.pub_b, auth_response.pub_y, envelope.priv_a, priv_x);

        // Return k1, t1 and X
        (AuthVerifyRequest {
            uid: String::from(&self.uid),
            client_verify_tag: ke_output.client_verify_tag,
            pub_x,
        }, ke_output)
    }

    /// Return OutputKey (K1)
    pub fn auth_finish(&self, auth_verify_response: AuthVerifyResponse, ke_output: KeyExchangeOutput) -> Option<OutputKey> {
        // Verify tag t2 and compute output key
        match auth_verify_response.server_verify_tag == Some(ke_output.server_verify_tag) { // TODO ok if none ?
            true => Some(ke_output.output_key),
            false => None,
        }
    }
}

// Server register
impl Server {
    /// Return RegisterResponse (B and oprf_server_evaluate_result), b and secret_salt
    pub fn register_start(&self, register_request: RegisterRequest) -> (RegisterResponse, PreRegisterSecrets) {
        // Generate asymmetric key
        let (priv_b, pub_b) = group::generate_keys();

        // Generate OPRF salt
        let secret_salt = oprf::generate_secret(self.parameters.use_oprf);

        // Compute OPRF server evaluate
        let server_evaluate_result = oprf::server_evaluate(self.parameters.use_oprf, register_request.oprf_client_blind_result, secret_salt);

        // Return B and h2 % TODO how to store salt and b (secret) ? Pre - store b and salt in file[uid] (remove it on server_register_finish) OR use a session_file[sid] < - (b, salt)
        (RegisterResponse {
            pub_b,
            oprf_server_evalute_result: server_evaluate_result,
        },
         PreRegisterSecrets {
             private_key: priv_b,
             secret_salt
         })
    }

    pub fn register_finish(&self, register_finish: RegisterFinish, pre_register_secrets: PreRegisterSecrets) -> FileEntry {
        // Store (e, b, A, salt)
        FileEntry {
            encrypted_envelope: register_finish.encrypted_envelope,
            priv_b: pre_register_secrets.private_key,
            pub_a: register_finish.pub_a,
            secret_salt: pre_register_secrets.secret_salt
        }
    }
}

// Server login
impl Server {
    /// Return AuthResponse (e, Y, oprf_server_evalute_result) and EphemeralKeys (server Y and y)
    pub fn auth_start(&self, auth_request: AuthRequest, file_entry: &FileEntry) -> (AuthResponse, EphemeralKeys) {
        // Generate asymmetric key
        let (priv_y, pub_y) = group::generate_keys();

        // Retrieve (e, salt) from file
        let secret_salt = file_entry.secret_salt.clone();
        let encrypted_envelope = file_entry.encrypted_envelope.clone();

        // Compute OPRF server evaluate
        let server_evaluate_result = oprf::server_evaluate(self.parameters.use_oprf, auth_request.oprf_client_blind_result, secret_salt);

        // Return e, Y, y, h2 % TODO how to store y ? Store in file[uid] (remove it on server_auth_finish) OR use a session_file[sid] <- (y)
        (AuthResponse {
            encrypted_envelope,
            pub_y,
            oprf_server_evalute_result: server_evaluate_result,
        },
         EphemeralKeys {
             private: priv_y,
             public: pub_y,
         })
    }

    /// Return AuthVerifyResponse (t2) and OutputKey (K2)
    pub fn auth_finish(&self, auth_verify_request: AuthVerifyRequest, ephemeral_keys: EphemeralKeys, file_entry: &FileEntry) -> (AuthVerifyResponse, Option<OutputKey>) {
        // Retrieve (b, A) from file
        let priv_b = file_entry.priv_b.clone();
        let pub_a = file_entry.pub_a.clone();

        // Compute KeyHidingAKE
        let ke_output = tripledh::compute_server(pub_a, auth_verify_request.pub_x, priv_b, ephemeral_keys.private);

        // Verify tag t1 and compute tag t2 and output key
        let (server_verify_tag, server_output_key) = match auth_verify_request.client_verify_tag == ke_output.client_verify_tag {
            true => (
                Some(ke_output.server_verify_tag),
                Some(ke_output.output_key)
            ),
            false => (None, None),
        };

        // Return K2, t2 % TODO what to do with K2 (session key) ? Store in db ? Expiration ? use a session_file[sid] <- K
        (AuthVerifyResponse {
            server_verify_tag,
        }, server_output_key)
    }
}



//////////////////////////////////////////////
//                   TEST                   //
//////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_with_serialization() {
        let uid = "1234";
        let password = b"test";

        let param = Parameters {
            use_oprf: true,
            use_slow_hash: false
        };
        let client = Client::new(param, String::from(uid));
        let server = Server::new(param);


        let (register_request, oprf_client_state) = client.register_start(password);

        let register_request_serialized = serde_json::to_string(&register_request).unwrap();
        println!("Sending register request : {:?}", register_request_serialized);
        let register_request_deserialized: RegisterRequest = serde_json::from_str(&register_request_serialized).unwrap();

        let (register_response, pre_register_secrets) = server.register_start(register_request_deserialized);

        let register_response_serialized = serde_json::to_string(&register_response).unwrap();
        println!("Sending register response : {:?}", register_response_serialized);
        let register_response_deserialized: RegisterResponse = serde_json::from_str(&register_response_serialized).unwrap();

        let register_finish = client.register_finish(register_response_deserialized, oprf_client_state);

        let register_finish_serialized = serde_json::to_string(&register_finish).unwrap();
        println!("Sending register finish : {:?}", register_finish_serialized);
        let register_finish_deserialized: RegisterFinish = serde_json::from_str(&register_finish_serialized).unwrap();

        let file_entry = server.register_finish(register_finish_deserialized, pre_register_secrets);
    }

    fn register(param: Parameters, uid: &str, password: &[u8]) -> FileEntry {
        let client = Client::new(param, String::from(uid));
        let server = Server::new(param);

        let (register_request, oprf_client_state) = client.register_start(password);
        let (register_response, pre_register_secrets) = server.register_start(register_request);
        let register_finish = client.register_finish(register_response, oprf_client_state);
        server.register_finish(register_finish, pre_register_secrets)
    }

    fn auth(param: Parameters, uid: &str, password: &[u8], file_entry: FileEntry) -> (Option<OutputKey>, Option<OutputKey>) {
        let client = Client::new(param, String::from(uid));
        let server = Server::new(param);

        let (auth_request, oprf_client_state) = client.auth_start(password);
        let (auth_response, server_ephemeral_keys) = server.auth_start(auth_request, &file_entry);
        let (auth_verify_request, k1) = client.auth_ke(auth_response, oprf_client_state);
        let (auth_verify_response, server_output_key) = server.auth_finish(auth_verify_request, server_ephemeral_keys, &file_entry);
        let client_output_key = client.auth_finish(auth_verify_response, k1);
        (client_output_key, server_output_key)
    }

    #[test]
    fn test_auth_same_password() {
        let param = Parameters {
            use_oprf: true,
            use_slow_hash: false
        };
        let uid = "1234";
        let password = b"test";

        let file_entry = register(param, uid, password);
        let (client_output_key, server_output_key) = auth(param, uid, password, file_entry);

        assert!(client_output_key.is_some());
        assert_eq!(client_output_key, server_output_key);
    }

    #[test]
    fn test_auth_different_password() {
        let param = Parameters {
            use_oprf: true,
            use_slow_hash: false
        };
        let uid = "1234";
        let password_register = b"test";
        let password_auth = b"testt";

        let file_entry = register(param, uid, password_register);
        let (client_output_key, server_output_key) = auth(param, uid, password_auth, file_entry);

        assert!(client_output_key.is_none());
        assert!(server_output_key.is_none());
        assert_eq!(client_output_key, server_output_key);
    }
}