pragma circom 2.1.2;

include "./secp256k1/poseidon/poseidon.circom";


/** 
 * Reconstruct root of binary merkle tree given leaves
 * (N, L) = (Number of leaves, Depth)
 * Private inputs:
 *      - merkle tree leaves
 *
 * Output:
 *      - root of the reconstructed merkle tree
 */ 
template ReconstructRoot(N, L) {
    // Private inputs
    signal input leaves[N];

    // Output
    signal output root;

    var LEAVES_PER_NODE = 2;
    var numLeafHashers = LEAVES_PER_NODE ** (L - 1);

    var i;
    var j;
   
    var numHashers = 0;
    for (i = 0; i < L; i ++) {
        numHashers += LEAVES_PER_NODE ** i;
    }

    component hashers[numHashers];

   // Instantiate all hashers
    for (i = 0; i < numHashers; i ++) {
        hashers[i] = Poseidon(2);
    }

    // Wire the leaf values into the leaf hashers
    for (i = 0; i < numLeafHashers; i ++){
        for (j = 0; j < LEAVES_PER_NODE; j ++){
            hashers[i].inputs[j] <== leaves[i * LEAVES_PER_NODE + j];
        }
    }

    // Wire the outputs of the leaf hashers to the intermediate hasher inputs
    var k = 0;
    for (i = numLeafHashers; i < numHashers; i ++) {
        for (j = 0; j < LEAVES_PER_NODE; j ++){
            hashers[i].inputs[j] <== hashers[k * LEAVES_PER_NODE + j].out;
        }
        k ++;
    }

    // Wire the output of the final hash to this circuit's output
    root <== hashers[numHashers-1].out;

}
