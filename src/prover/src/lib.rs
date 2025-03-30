mod prover;

use std::path::PathBuf;
use libspartan::NIZK;
use prover::prove_circuit;
use circuit_reader::load_as_spartan_inst;
use witness_reader::load_witness_from_bin;

pub fn prove(circom_r1cs_path: PathBuf, witness_path: PathBuf) -> NIZK {
    let (inst, n_pub_inputs, n_pub_outputs) = load_as_spartan_inst(circom_r1cs_path);
    
    let (assignment_vars, assignment_inputs, _) = load_witness_from_bin(witness_path, n_pub_inputs as u32, n_pub_outputs as u32).unwrap();

    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    assert_eq!(res.unwrap(), true);

    prove_circuit(inst, assignment_vars, assignment_inputs)
}