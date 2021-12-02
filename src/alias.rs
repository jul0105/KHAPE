pub(crate) type Group = curve25519_dalek::ristretto::RistrettoPoint;
pub(crate) type Hash = sha3::Sha3_256;
pub(crate) type RawPublicKey = curve25519_dalek::montgomery::MontgomeryPoint;
pub(crate) type SharedKey = curve25519_dalek::montgomery::MontgomeryPoint;
pub(crate) type PublicKey = curve25519_dalek::field::FieldElement;
pub(crate) type PrivateKey = curve25519_dalek::scalar::Scalar;

pub type PreKey = [u8; 32];
pub type OutputKey = [u8; 32];
pub(crate) type VerifyTag = OutputKey;
pub(crate) type FileStorage = Vec<crate::message::FileEntry>;

pub type OprfClientState = voprf::NonVerifiableClient<Group, Hash>;
