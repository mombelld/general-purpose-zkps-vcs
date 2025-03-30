mod circom_reader;

use circom_reader::{load_r1cs_from_bin_file, R1CS};
use ff::PrimeField;
use libspartan::Instance;
use secq256k1::AffinePoint;
use secq256k1::FieldBytes;
use std::path::PathBuf;

pub fn load_as_spartan_inst(circuit_file: PathBuf) -> (Instance, usize, usize) {
    let (r1cs, _) = load_r1cs_from_bin_file::<AffinePoint>(&circuit_file);
    let n_pub_inputs = r1cs.num_inputs - 1;
    let n_outs = r1cs.num_outputs;
    let spartan_inst = convert_to_spartan_r1cs(&r1cs, n_pub_inputs);
    (spartan_inst, n_pub_inputs, n_outs)
}

// We need to remap the wires ids because circom does ONE||pub||priv while spartan dose priv||ONE||pub
fn remap_id(id: usize, n_vars: usize, n_inps: usize) -> usize {
    
    if id == 0 {
        return n_vars;
    }

    if id <= n_inps {
        return id + n_vars;
    }

    return id - n_inps - 1;

}

fn convert_to_spartan_r1cs<F: PrimeField<Repr = FieldBytes>>(
    r1cs: &R1CS<F>,
    num_pub_inputs: usize,
) -> Instance {
    let num_cons = r1cs.constraints.len();
    let num_vars = r1cs.num_variables;
    let num_inputs = num_pub_inputs;

    let mut A = vec![];
    let mut B = vec![];
    let mut C = vec![];

    for (i, constraint) in r1cs.constraints.iter().enumerate() {
        let (a, b, c) = constraint;

        for (j, coeff) in a.iter() {
            let bytes: [u8; 32] = coeff.to_repr().into();

            A.push((i, remap_id(*j, num_vars, num_inputs), bytes));
        }

        for (j, coeff) in b.iter() {
            let bytes: [u8; 32] = coeff.to_repr().into();
            B.push((i, remap_id(*j, num_vars, num_inputs), bytes));
        }

        for (j, coeff) in c.iter() {
            let bytes: [u8; 32] = coeff.to_repr().into();
            C.push((i, remap_id(*j, num_vars, num_inputs), bytes));
        }
    }

    let inst = Instance::new(
        num_cons,
        num_vars,
        num_inputs,
        A.as_slice(),
        B.as_slice(),
        C.as_slice(),
    )
    .unwrap();

    inst
}
