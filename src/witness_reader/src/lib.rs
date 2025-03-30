mod witness_reader;
use libspartan::{InputsAssignment, VarsAssignment};
use std::io::Error;
use witness_reader::load_witness_from_bin_reader;
use std::path::PathBuf;


pub fn load_witness_from_bin(witness_file: PathBuf, num_pub_inputs: u32, num_put_outputs: u32) -> Result<(VarsAssignment, InputsAssignment, Vec<[u8; 32]>), Error> {
    load_witness_from_bin_reader(witness_file, num_pub_inputs, num_put_outputs)
}