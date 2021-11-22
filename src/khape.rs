

type CurvePoint = String;
type OprfValue = String;
type Envelope = String;
type FileEntry = String;


struct RegisterRequest {
    uid: String,
    h1: OprfValue, // oprf init
}

struct RegisterResponse {
    B: CurvePoint, // curve point
    h2: OprfValue, // oprf init
}

struct RegisterFinish {
    e: Envelope, // Encrypted enveloppe
    A: CurvePoint // curve point
}


pub fn client_register_start(uid: &str, pw: &str) -> RegisterRequest {
    // compute OPRF initialization
    // add OPRF h1 and uid to a struct
    // return struct
}

// Sends uid and h1 (RegisterRequest)

pub fn server_register_start(register_request: RegisterRequest) -> (RegisterResponse, CurvePoint, OprfValue) {
    // generate_asymetric_key
    // generate OPRF salt
    // compute OPRF h2
    // return B and h2 % TODO how to store salt and b (secret) ? Pre - store b and salt in file[uid] (remove it on server_register_finish) OR use a session_file[sid] < - (b, salt)
}

// Response B and h2 (RegisterResponse)

pub fn client_register_finish(register_response: RegisterResponse, pw: &str) -> RegisterFinish {
    // generate_asymetric_key
    // compute OPRF output
    // encrypt (a, B) with rw
    // return ciphertext
}

// Sends e and A (RegisterFinish)

pub fn server_register_finish(register_finish: RegisterFinish, b: CurvePoint, salt: OprfValue) -> FileEntry {
    // store (e, b, A, salt)
}