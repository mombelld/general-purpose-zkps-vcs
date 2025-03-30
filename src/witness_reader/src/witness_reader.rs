use byteorder::{LittleEndian, ReadBytesExt};
use std::fs;
use libspartan::{InputsAssignment, VarsAssignment};
use std::io::{Error, Read};
use std::path::PathBuf;

pub fn load_witness_from_bin_reader(witness_file: PathBuf, num_pub_inputs: u32, num_pub_outputs: u32) -> Result<(VarsAssignment, InputsAssignment, Vec<[u8; 32]>), Error> {
    let binding = fs::read(witness_file).unwrap();
    let mut reader = binding.as_slice();
    
    let mut wtns_header = [0u8; 4];
    reader.read_exact(&mut wtns_header)?;
    if wtns_header != [119, 116, 110, 115] {
        // ruby -e 'p "wtns".bytes' => [119, 116, 110, 115]
        panic!("invalid file header");
    }

    let version = reader.read_u32::<LittleEndian>()?;
    if version > 2 {
        panic!("unsupported file version");
    }

    let num_sections = reader.read_u32::<LittleEndian>()?;
    if num_sections != 2 {
        panic!("invalid num sections");
    }

    // read first section
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 1 {
        panic!("invalid section type");
    }

    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != 4 + 32 + 4 {
        panic!("invalid section len")
    }

    let field_size = reader.read_u32::<LittleEndian>()?;
    if field_size != 32 {
        panic!("invalid field byte size");
    }

    let mut prime = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime)?;


    let witness_len = reader.read_u32::<LittleEndian>()?;

    // read second section
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 2 {
        panic!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != (witness_len * field_size) as u64 {
        panic!("invalid witness section size {}", sec_size);
    }

    let mut inputs: Vec<[u8; 32]> = Vec::with_capacity(num_pub_inputs as usize);

    let n_vars = witness_len - num_pub_inputs - 1;
    let mut vars: Vec<[u8; 32]> = Vec::with_capacity(n_vars as usize);
    
    for i in 0..witness_len {
        let mut tmp: [u8; 32] = [0u8; 32];
        reader.read_exact(&mut tmp)?;

        if 0 < i && i <= num_pub_inputs {
            inputs.push(tmp.clone());
        }

        if num_pub_inputs < i {
            vars.push(tmp.clone());
        }
    }
    let assignment_inputs = InputsAssignment::new(&inputs).unwrap();
    let assignment_vars = VarsAssignment::new(&vars).unwrap();
    let assignment_outputs = inputs[0..num_pub_outputs as usize].to_vec();

    Ok((assignment_vars, assignment_inputs, assignment_outputs))
}