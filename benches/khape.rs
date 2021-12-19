use criterion::{black_box, criterion_group, criterion_main, Criterion};

use khape::*;
use rand::{thread_rng, Rng};
use std::convert::TryFrom;

const USE_OPRF: bool = true;
const USE_SLOW_HASH: bool = false;

pub fn client_initialization(c: &mut Criterion) {
    let uid = "username";

    c.bench_function("client_initialization", |b| b.iter(|| Client::new(Parameters::new(USE_OPRF, USE_SLOW_HASH), String::from(uid))));
}

pub fn server_initialization(c: &mut Criterion) {
    c.bench_function("server_initialization", |b| b.iter(|| Server::new(Parameters::new(USE_OPRF, USE_SLOW_HASH))));
}


pub fn client_register_start(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = String::from("username");
    let password = b"password";
    let client = Client::new(params, uid);

    c.bench_function("client_register_start", |b| b.iter(|| client.register_start(black_box(password))));
}

pub fn server_register_start(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = String::from("username");
    let password = b"password";
    let client = Client::new(params, uid);
    let server = Server::new(params);

    let (register_request, _) = client.register_start(password);

    c.bench_function("server_register_start", |b| b.iter(|| server.register_start(black_box(register_request.clone()))));
}

pub fn client_register_finish(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = String::from("username");
    let password = b"password";
    let client = Client::new(params, uid);
    let server = Server::new(params);

    let (register_request, oprf_client_state) = client.register_start(password);
    let (register_response, _) = server.register_start(register_request);

    c.bench_function("client_register_finish", |b| b.iter(|| client.register_finish(black_box(register_response.clone()), black_box(oprf_client_state.clone()))));
}

pub fn server_register_finish(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = String::from("username");
    let password = b"password";
    let client = Client::new(params, uid);
    let server = Server::new(params);

    let (register_request, oprf_client_state) = client.register_start(password);
    let (register_response, pre_register_secrets) = server.register_start(register_request);
    let register_finish = client.register_finish(register_response, oprf_client_state);

    c.bench_function("server_register_finish", |b| b.iter(|| server.register_finish(black_box(register_finish.clone()), black_box(pre_register_secrets.clone()))));
}



pub fn client_auth_start(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = String::from("username");
    let password = b"password";
    let client = Client::new(params, uid);
    let server = Server::new(params);

    let (register_request, oprf_client_state) = client.register_start(password);
    let (register_response, pre_register_secrets) = server.register_start(register_request);
    let register_finish = client.register_finish(register_response, oprf_client_state);
    let _ = server.register_finish(register_finish, pre_register_secrets);

    c.bench_function("client_auth_start", |b| b.iter(|| client.auth_start(black_box(password))));
}

pub fn server_auth_start(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = String::from("username");
    let password = b"password";
    let client = Client::new(params, uid);
    let server = Server::new(params);

    let (register_request, oprf_client_state) = client.register_start(password);
    let (register_response, pre_register_secrets) = server.register_start(register_request);
    let register_finish = client.register_finish(register_response, oprf_client_state);
    let file_entry = server.register_finish(register_finish, pre_register_secrets);

    let (auth_request, _) = client.auth_start(password);

    c.bench_function("server_auth_start", |b| b.iter(|| server.auth_start(black_box(auth_request.clone()), black_box(&file_entry))));
}

pub fn client_auth_ke(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = String::from("username");
    let password = b"password";
    let client = Client::new(params, uid);
    let server = Server::new(params);

    let (register_request, oprf_client_state) = client.register_start(password);
    let (register_response, pre_register_secrets) = server.register_start(register_request);
    let register_finish = client.register_finish(register_response, oprf_client_state);
    let file_entry = server.register_finish(register_finish, pre_register_secrets);

    let (auth_request, oprf_client_state) = client.auth_start(password);
    let (auth_response, _) = server.auth_start(auth_request, &file_entry);

    c.bench_function("client_auth_ke", |b| b.iter(|| client.auth_ke(black_box(auth_response.clone()), black_box(oprf_client_state.clone()))));
}

pub fn server_auth_finish(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = String::from("username");
    let password = b"password";
    let client = Client::new(params, uid);
    let server = Server::new(params);

    let (register_request, oprf_client_state) = client.register_start(password);
    let (register_response, pre_register_secrets) = server.register_start(register_request);
    let register_finish = client.register_finish(register_response, oprf_client_state);
    let file_entry = server.register_finish(register_finish, pre_register_secrets);

    let (auth_request, oprf_client_state) = client.auth_start(password);
    let (auth_response, server_ephemeral_keys) = server.auth_start(auth_request, &file_entry);
    let (auth_verify_request, _) = client.auth_ke(auth_response, oprf_client_state);

    c.bench_function("server_auth_finish", |b| b.iter(|| server.auth_finish(black_box(auth_verify_request.clone()), black_box(server_ephemeral_keys.clone()), black_box(&file_entry))));
}

pub fn client_auth_finish(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = String::from("username");
    let password = b"password";
    let client = Client::new(params, uid);
    let server = Server::new(params);

    let (register_request, oprf_client_state) = client.register_start(password);
    let (register_response, pre_register_secrets) = server.register_start(register_request);
    let register_finish = client.register_finish(register_response, oprf_client_state);
    let file_entry = server.register_finish(register_finish, pre_register_secrets);

    let (auth_request, oprf_client_state) = client.auth_start(password);
    let (auth_response, server_ephemeral_keys) = server.auth_start(auth_request, &file_entry);
    let (auth_verify_request, ke_output) = client.auth_ke(auth_response, oprf_client_state);
    let (auth_verify_response, _) = server.auth_finish(auth_verify_request, server_ephemeral_keys, &file_entry);

    c.bench_function("client_auth_finish", |b| b.iter(|| client.auth_finish(black_box(auth_verify_response.clone()), black_box(ke_output.clone()))));
}

fn register(param: Parameters, uid: &str, password: &[u8]) -> FileEntry {
    let client = Client::new(param, String::from(uid));
    let server = Server::new(param);

    let (register_request, oprf_client_state) = client.register_start(password);
    let (register_response, pre_register_secrets) = server.register_start(register_request);
    let register_finish = client.register_finish(register_response, oprf_client_state);
    server.register_finish(register_finish, pre_register_secrets)
}

fn auth(param: Parameters, uid: &str, password: &[u8], file_entry: &FileEntry) -> (Option<OutputKey>, Option<OutputKey>) {
    let client = Client::new(param, String::from(uid));
    let server = Server::new(param);

    let (auth_request, oprf_client_state) = client.auth_start(password);
    let (auth_response, server_ephemeral_keys) = server.auth_start(auth_request, file_entry);
    let (auth_verify_request, ke_output) = client.auth_ke(auth_response, oprf_client_state);
    let (auth_verify_response, server_output_key) = server.auth_finish(auth_verify_request, server_ephemeral_keys, file_entry);
    let client_output_key = client.auth_finish(auth_verify_response, ke_output);
    (client_output_key, server_output_key)
}

pub fn overall_register(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = "username";
    let password = b"password";

    c.bench_function("overall_register", |b| b.iter(|| register(black_box(params), black_box(uid), black_box(password))));
}

pub fn overall_auth(c: &mut Criterion) {
    let params = Parameters::new(USE_OPRF, USE_SLOW_HASH);
    let uid = "username";
    let password = b"password";
    let file_entry = register(params, uid, password);

    c.bench_function("overall_auth", |b| b.iter(|| auth(black_box(params), black_box(uid), black_box(password), black_box(&file_entry))));
}



pub fn group_generate_keys(c: &mut Criterion) {
    c.bench_function("group_generate_keys", |b| b.iter(|| generate_keys_pub()));
}

pub fn group_compute_shared_key(c: &mut Criterion) {
    let (priv_a, _) = generate_keys_pub();
    let (_, pub_b) = generate_keys_pub();

    c.bench_function("group_compute_shared_key", |b| b.iter(|| compute_shared_key_pub(black_box(priv_a), black_box(pub_b))));
}

pub fn tripledh_compute_client(c: &mut Criterion) {
    let (priv_a, _) = generate_keys_pub();
    let (_, pub_b) = generate_keys_pub();
    let (priv_x, _) = generate_keys_pub();
    let (_, pub_y) = generate_keys_pub();

    c.bench_function("tripledh_compute_client", |b| b.iter(|| compute_client_pub(black_box(pub_b), black_box(pub_y), black_box(priv_a), black_box(priv_x))));
}

pub fn tripledh_compute_server(c: &mut Criterion) {
    let (_, pub_a) = generate_keys_pub();
    let (priv_b, _) = generate_keys_pub();
    let (_, pub_x) = generate_keys_pub();
    let (priv_y, _) = generate_keys_pub();

    c.bench_function("tripledh_compute_server", |b| b.iter(|| compute_server_pub(black_box(pub_a), black_box(pub_x), black_box(priv_b), black_box(priv_y))));
}

pub fn ideal_cipher_encryption(c: &mut Criterion) {
    let key = thread_rng().gen::<[u8; 32]>();
    let (priv_a, _) = generate_keys_pub();
    let (_, pub_b) = generate_keys_pub();
    let plaintext = <[u8; 64]>::try_from([priv_a.to_bytes(), pub_b.to_bytes()].concat()).unwrap();

    c.bench_function("ideal_cipher_encryption", |b| b.iter(|| encrypt_feistel_pub(key, plaintext)));
}

pub fn ideal_cipher_decryption(c: &mut Criterion) {
    let key = thread_rng().gen::<[u8; 32]>();
    let (priv_a, _) = generate_keys_pub();
    let (_, pub_b) = generate_keys_pub();
    let plaintext = <[u8; 64]>::try_from([priv_a.to_bytes(), pub_b.to_bytes()].concat()).unwrap();
    let ciphertext = encrypt_feistel_pub(key, plaintext);

    c.bench_function("ideal_cipher_decryption", |b| b.iter(|| decrypt_feistel_pub(key, ciphertext)));
}


criterion_group!(
    benches,
    client_initialization,
    server_initialization,
    client_register_start,
    server_register_start,
    client_register_finish,
    server_register_finish,
    client_auth_start,
    server_auth_start,
    client_auth_ke,
    server_auth_finish,
    client_auth_finish,
);
criterion_group!(
    beanches_overall,
    overall_register,
    overall_auth,
);
criterion_group!(
    benches_component,
    group_generate_keys,
    group_compute_shared_key,
    tripledh_compute_client,
    tripledh_compute_server,
    ideal_cipher_encryption,
    ideal_cipher_decryption,
);
criterion_main!(benches, beanches_overall, benches_component);