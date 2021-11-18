use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, X25519_BASEPOINT};

pub fn try_triple_dh() {
    let a: Scalar = compute_private_key([1u8; 32]);
    let b: Scalar = compute_private_key([2u8; 32]);
    let A: MontgomeryPoint = compute_public_key(a);
    let B: MontgomeryPoint = compute_public_key(b);


    let x: Scalar = compute_private_key([3u8; 32]);
    let y: Scalar = compute_private_key([4u8; 32]);
    let X: MontgomeryPoint = compute_public_key(x);
    let Y: MontgomeryPoint = compute_public_key(y);

    // B^x || Y^a || Y^x
    let o_client_1 = compute_shared_key(x.to_bytes(), B.to_bytes());
    let o_client_2 = compute_shared_key(a.to_bytes(), Y.to_bytes());
    let o_client_3 = compute_shared_key(x.to_bytes(), Y.to_bytes());
    let o_client = [o_client_1, o_client_2, o_client_3].concat();

    // X^b || A^y || X^y
    let o_server_1 = compute_shared_key(b.to_bytes(), X.to_bytes());
    let o_server_2 = compute_shared_key(y.to_bytes(), A.to_bytes());
    let o_server_3 = compute_shared_key(y.to_bytes(), X.to_bytes());
    let o_server = [o_server_1, o_server_2, o_server_3].concat();

    assert_eq!(o_client_1, o_server_1);
    assert_eq!(o_client_2, o_server_2);
    assert_eq!(o_client_3, o_server_3);
    assert_eq!(o_client_1.len(), 32);
    assert_eq!(o_client_2.len(), 32);
    assert_eq!(o_client_3.len(), 32);

    assert_eq!(o_client, o_server);
    assert_eq!(o_client.len(), 32*3);

}

pub fn try_dalek_ecc() {
    let alice_private: Scalar = clamp_scalar([1u8; 32]);
    let bob_private: Scalar = clamp_scalar([2u8; 32]);
    let alice_public: MontgomeryPoint = (&ED25519_BASEPOINT_TABLE * &alice_private).to_montgomery();
    let bob_public: MontgomeryPoint = (&ED25519_BASEPOINT_TABLE * &bob_private).to_montgomery();

    let alice_public2: MontgomeryPoint = X25519_BASEPOINT * alice_private;

    assert_eq!(alice_public, alice_public2);

    let alice_shared = x25519(alice_private.to_bytes(), bob_public.to_bytes());
    let bob_shared = x25519(bob_private.to_bytes(), alice_public.to_bytes());

    assert_eq!(alice_shared, bob_shared);

}

pub fn try_dalek_ecc2() {
    let alice_private: Scalar = compute_private_key([1u8; 32]);
    let bob_private: Scalar = compute_private_key([2u8; 32]);
    let alice_public: MontgomeryPoint = compute_public_key(alice_private);
    let bob_public: MontgomeryPoint = compute_public_key(bob_private);

    let alice_shared = compute_shared_key(alice_private.to_bytes(), bob_public.to_bytes());
    let bob_shared = compute_shared_key(bob_private.to_bytes(), alice_public.to_bytes());

    assert_eq!(alice_shared, bob_shared);
}

fn compute_private_key(bytes: [u8; 32]) -> Scalar {
    clamp_scalar(bytes)
}

fn compute_public_key(private_key: Scalar) -> MontgomeryPoint {
    X25519_BASEPOINT * private_key
}

fn compute_shared_key(own_private_key: [u8; 32], opposing_public_key: [u8; 32]) -> [u8; 32] {
    (clamp_scalar(own_private_key) * MontgomeryPoint(opposing_public_key)).to_bytes() // From x25519-dalek library
}



fn x25519(k: [u8; 32], u: [u8; 32]) -> [u8; 32] {
    (clamp_scalar(k) * MontgomeryPoint(u)).to_bytes() // From x25519-dalek library
}

fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar { // From x25519-dalek library
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Scalar::from_bits(scalar)
}