//! # Usage
//!
//! ## Parameters
//!
//! ```
//! use khape::Parameters;
//! let params = Parameters::default();
//! ```
//!
//! ## Registration
//!
//! ### 1. Client Registration Start
//! ```
//! use khape::Client;
//! let uid = String::from("john123");
//! let password = b"password123";
//!
//! let client = Client::new(params, uid);
//! let (register_request, oprf_client_state) = client.register_start(password);
//! ```
//! Client sends `register_request` to the server and keeps `oprf_client_state`.
//!
//! ### 2. Server Registration Start
//! ```
//! use khape::Server;
//! let server = Server::new(params);
//! let (register_response, pre_register_secrets) = server.register_start(register_request);
//! ```
//! Server sends `register_response` back to the client and stores `pre_register_secrets` on the server using `register_request.uid` as index.
//!
//! ### 3. Client Registration Finish
//! ```
//! let register_finish = client.register_finish(register_response, oprf_client_state);
//! ```
//! Client sends `register_finish` to the server.
//!
//! ### 4. Server Registration Finish
//! Server retrieves stored `pre_register_secrets` indexed with `register_finish.uid`.
//! ```
//! let file_entry = server.register_finish(register_finish, pre_register_secrets);
//! ```
//! Server stores `file_entry` on the server using `register_finish.uid` as index.
//!
//! ## Login
//!
//! ### 1. Client Login Start
//! ```
//! use khape::Client;
//! let uid = String::from("john123");
//! let password = b"password123";
//!
//! let client = Client::new(params, uid);
//! let (auth_request, oprf_client_state) = client.auth_start(password);
//! ```
//! Client sends `register_request` to the server and keeps `oprf_client_state`.
//!
//! ### 2. Server Login Start
//! Server retrieves user's `file_entry` from storage using `auth_request.uid` as index.
//! ```
//! use khape::Server;
//! let server = Server::new(params);
//! let (auth_response, server_ephemeral_keys) = server.auth_start(auth_request, &file_entry);
//! ```
//! Server sends `auth_response` back to the client and store `server_ephemeral_keys` using `auth_request.uid` or `auth_request.sid` as index.
//! `server_ephemeral_keys` can be stored alongside user's file_entry in a user datastore (indexed with uid) or in a separated session datastore (indexed with sid)
//!
//!
//! ### 3. Client Login Key Exchange
//! ```
//! let (auth_verify_request, ke_output) = client.auth_ke(auth_response, oprf_client_state);
//! ```
//! Client sends `auth_verify_request` to the server and keep `ke_output`.
//!
//! ### 4. Server Login Finish
//! Server retrieves user's `file_entry` from storage using `auth_verify_request.uid` as index.
//! Server also retrieves user's specific `server_ephemeral_keys` from server storage using `auth_verify_request.uid`.
//! ```
//! let (auth_verify_response, server_output_key) = server.auth_finish(auth_verify_request, server_ephemeral_keys, &file_entry);
//! ```
//! Server sends `auth_verify_response` back to the client and he can use the session key `server_output_key` after verifying its validity (Option) ,
//!
//! ### 5. Client Login Finish
//! ```
//! let client_output_key = client.auth_finish(auth_verify_response, ke_output);
//! ```
//! Client can use the session key `client_output_key` after verifying its validity (Option).

mod khape;
mod oprf;
mod group;
mod tripledh;
mod encryption;
mod key_derivation;
mod ideal_cipher;
mod message;
mod alias;
mod slow_hash;

// KHAPE functions
pub use crate::khape::{Client, Parameters, Server};
// KHAPE messages
pub use crate::message::{AuthRequest, AuthResponse, AuthVerifyRequest, AuthVerifyResponse, RegisterFinish, RegisterRequest, RegisterResponse};
// Server struct
pub use crate::message::{EphemeralKeys, FileEntry, PreRegisterSecrets};
// Alias
pub use crate::alias::{OutputKey};
