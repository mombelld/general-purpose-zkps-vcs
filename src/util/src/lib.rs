mod util;
use util::serialize_proof;
use libspartan::NIZK;

pub fn proof_to_file(proof: NIZK, n_pub_out: u32, n_pub_in: u32) {
    serialize_proof(proof, n_pub_out, n_pub_in);
}
