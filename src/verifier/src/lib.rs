mod verifier;

use verifier::verify_circuit;
use libspartan::{InputsAssignment, Instance, NIZK};

pub fn verify(circuit: Instance, proof: NIZK, assignment_inputs: InputsAssignment) -> bool {
    verify_circuit(circuit, proof, assignment_inputs)
}