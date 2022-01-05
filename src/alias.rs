pub(crate) type Group = curve25519_dalek::ristretto::RistrettoPoint;
pub(crate) type Hash = sha3::Sha3_256;
pub(crate) type RawPublicKey = curve25519_dalek::montgomery::MontgomeryPoint;
pub(crate) type SharedKey = curve25519_dalek::montgomery::MontgomeryPoint;
pub(crate) type PublicKey = curve25519_dalek::field::FieldElement;
pub(crate) type PrivateKey = curve25519_dalek::scalar::Scalar;

pub type OutputKey = [u8; KEY_SIZE];
pub type ExportKey = [u8; KEY_SIZE];
pub(crate) type VerifyTag = OutputKey;
pub type OprfClientState = voprf::NonVerifiableClient<Group, Hash>;


pub const KEY_SIZE: usize = 32;
pub const CIPHER_SIZE: usize = KEY_SIZE * 2;
pub const FEISTEL_PART_SIZE: usize = KEY_SIZE;
pub const OPRF_SALT_SIZE: usize = KEY_SIZE;

pub const ARGON2_M_COST: u32 = 16*1024;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;
