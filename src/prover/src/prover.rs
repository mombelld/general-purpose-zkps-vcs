use libspartan::{InputsAssignment, Instance, NIZKGens, VarsAssignment, NIZK};
use merlin::Transcript;


const SEP: &[u8; 4] = b"zkvc";

pub fn prove_circuit(circuit: Instance, assignment_vars: VarsAssignment, assignment_inputs: InputsAssignment) -> NIZK {
    
    let num_cons = circuit.inst.get_num_cons();
    let num_vars = circuit.inst.get_num_vars();
    let num_inputs = circuit.inst.get_num_inputs();

    // Produce public parameters
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    // Produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(SEP);
    let proof = NIZK::prove(&circuit, assignment_vars.clone(), &assignment_inputs, &gens, &mut prover_transcript);

    proof
}