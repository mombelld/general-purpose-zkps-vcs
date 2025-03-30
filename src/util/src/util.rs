use libspartan::{NIZK, InputsAssignment};
use secq256k1::{elliptic_curve::{bigint::Encoding, Curve}, Secq256K1};
// use primeorder::elliptic_curve::bigint::U256;

const MAGIC: &[u8; 4] = b"zkvc";

pub fn serialize_proof(proof: NIZK, n_pub_out: u32, n_pub_in: u32) {
    let vers: Vec<u8> = vec![0x01, 0x00, 0x00, 0x00];
    let nsec: Vec<u8> = vec![0x03, 0x00, 0x00, 0x00];
    
    let hdrs: Vec<u8> = vec![0x01, 0x00, 0x00, 0x00];
    let pios: Vec<u8> = vec![0x02, 0x00, 0x00, 0x00];
    let prfs: Vec<u8> = vec![0x03, 0x00, 0x00, 0x00];

    let fsbt: Vec<u8> = vec![0x20, 0x00, 0x00, 0x00];
    let prime = Secq256K1::ORDER.to_le_bytes();

    let npout: [u8; 4] = n_pub_out.to_le_bytes();
    let npin: [u8; 4] = n_pub_in.to_le_bytes();


}