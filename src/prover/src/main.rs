use bincode;
use std::env::{args, current_dir};
use std::fs::File;
use std::io::Write;
use prover::prove;

fn main() {

    let circom_r1cs_path = args().nth(1).unwrap();
    let witness_path = args().nth(2).unwrap();
    let out_path = args().nth(3).unwrap();

    let root = current_dir().unwrap();
    let circom_r1cs_path = root.join(circom_r1cs_path);
    let witness_path = root.join(witness_path);


    let proof = prove(circom_r1cs_path, witness_path);

    // Write proof to output file
    let proof_encoded: Vec<u8> = bincode::serialize(&proof).unwrap();

    File::create(root.join(out_path.clone()))
        .unwrap()
        .write_all(proof_encoded.as_slice())
        .unwrap();

}


