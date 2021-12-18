use criterion::{black_box, criterion_group, criterion_main, Criterion};

use khape::*;

const USE_OPRF: bool = false;
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
criterion_main!(benches);