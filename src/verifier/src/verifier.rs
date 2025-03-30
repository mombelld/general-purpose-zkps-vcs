use libspartan::{InputsAssignment, Instance, NIZKGens, NIZK};
use merlin::Transcript;

const SEP: &[u8; 4] = b"zkvc";

pub fn verify_circuit(circuit: Instance, proof: NIZK, assignment_inputs: InputsAssignment) -> bool{

    let num_cons = circuit.inst.get_num_cons();
    let num_vars = circuit.inst.get_num_vars();
    let num_inputs = circuit.inst.get_num_inputs();

    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);
    let mut verifier_transcript = Transcript::new(SEP);

    proof.verify(&circuit, &assignment_inputs, &mut verifier_transcript, &gens).is_ok()
}