use std::env::{args, current_dir};
use libspartan::Instance;
use prover::prove;
use verifier::verify;
use circuit_reader::load_as_spartan_inst;
use witness_reader::load_witness_from_bin;
use std::time::Instant;

fn main() {
    let circom_r1cs_path = args().nth(1).unwrap();
    let witness_path = args().nth(2).unwrap();

    let root = current_dir().unwrap();

    // Read Circom generate r1cs file

    let circom_r1cs_path = root.join(circom_r1cs_path);
    let witness_path = root.join(witness_path);

    println!("Loading proof...");
    let load_start = Instant::now();
    let (inst, n_pub_inputs, n_pub_outputs) = load_as_spartan_inst(circom_r1cs_path.clone());
    let load_time = load_start.elapsed().as_millis();
    println!("Circuit loaded in {:?} millisecs", load_time);

    // Read witness
    println!("Loading witness...");
    let wtns_start = Instant::now();
    let (_, assignment_inputs, assignment_outputs) = load_witness_from_bin(witness_path.clone(), n_pub_inputs as u32, n_pub_outputs as u32).unwrap();
    let wtns_time: u128 = wtns_start.elapsed().as_millis();
    println!("Witness loaded in {:?} millisecs", wtns_time);
    
    println!("Starting proof...");
    let prover_start = Instant::now();

    // --------------------------------------------------------
    let proof = prove(circom_r1cs_path, witness_path);
    // --------------------------------------------------------

    let prover_time = prover_start.elapsed().as_millis();
    println!("Statement proved in {:?} millisecs", prover_time);

    println!("Starting verification...");
    let verifier_start = Instant::now();

    // --------------------------------------------------------
    let valid = verify(inst, proof, assignment_inputs);
    // --------------------------------------------------------
    
    let verifier_time = verifier_start.elapsed().as_millis();
    println!("Statement verified in {:?} millisecs", verifier_time);

    if valid {
        println!("Proof successfully verified!");

    } else {
        println!("Invalid proof!");
        
    }
    println!("\n---------------------------");
    println!("Proof output: {:?}", assignment_outputs);
    println!("---------------------------");

}
