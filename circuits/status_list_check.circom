pragma circom 2.1.2;

include "./secp256k1/eff_ecdsa_membership/modular_arithmetic/bigint.circom";
include "./util/list_util.circom";

/**
 * Given a status list represented by a list of 256 bit integers and an index in the list, return 
 * the corresponding value. Each entry in the list i 2 bits
 *
 * Public inputs:
 *      - status_list
 *
 * Private inputs:
 *      - status_list_idx
 *
 * Output:
 *      - status_list[status_list_idx]
 */
template StatusListCheck(N, K, B) {
    // Public inputs
    signal input status_list[N];

    // Private inputs
    signal input status_list_idx;

    // Outputs
    signal output status;
    

    var entries_per_chunk = K / B;
    signal target_chunk <-- status_list_idx \ entries_per_chunk;
    signal position_in_chunk <-- status_list_idx % entries_per_chunk;
    status_list_idx === target_chunk * entries_per_chunk + position_in_chunk;

    // Select chunk
    component chunkSelector = ListSelector(N);
    chunkSelector.list <== status_list;
    chunkSelector.index <== target_chunk;
    signal chunk <== chunkSelector.selected;

    component bits = numToChunks(B, entries_per_chunk);
    bits.in <== chunk;
    signal chunk_bits[entries_per_chunk];
    chunk_bits <== bits.out;

    // Select entry
    component entrySelector = ListSelector(entries_per_chunk);
    entrySelector.list <== chunk_bits;
    entrySelector.index <== position_in_chunk;

    status <== entrySelector.selected;

}


// component main = StatusListCheck(1024, 256, 2);