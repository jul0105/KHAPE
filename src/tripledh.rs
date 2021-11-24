use crate::group::compute_shared_key;

pub fn compute_client() {
    // B^x || Y^a || Y^x
    // let o_client_1 = compute_shared_key(x.to_bytes(), B.to_bytes());
    // let o_client_2 = compute_shared_key(a.to_bytes(), Y.to_bytes());
    // let o_client_3 = compute_shared_key(x.to_bytes(), Y.to_bytes());
    // let o_client = [o_client_1, o_client_2, o_client_3].concat();
    unimplemented!()
}

pub fn compute_server() {
    // X^b || A^y || X^y
    // let o_server_1 = compute_shared_key(b.to_bytes(), X.to_bytes());
    // let o_server_2 = compute_shared_key(y.to_bytes(), A.to_bytes());
    // let o_server_3 = compute_shared_key(y.to_bytes(), X.to_bytes());
    // let o_server = [o_server_1, o_server_2, o_server_3].concat();
    unimplemented!()
}