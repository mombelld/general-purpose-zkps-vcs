pragma circom 2.1.2;

include "./secp256k1/eff_ecdsa_membership/ecdsa.circom";
include "./poseidon/poseidon.circom";
include "../circomlib/circuits/comparators.circom";


/** 
 * Verify credential's signature using issuers pk
 * (N, L) = (Number of leaves, Depth)
 * TODO: explain signature
 * Public inputs:
 *      - issuer's public key (x, y)
 * Private inputs:
 *      - array of hashed claims, where an hashed claim is Poseidon([claim_name, claim_value]), claim_value could 
 *        1 or more elements (up to a maximum of 15)
 *      - credential signature (r, s)
 *
 * Output:
 *      - signature validity \in {0, 1}
 */ 
template VerifyCredentialSignature(N) {
    assert(N <= 256);
    var hash_width = 16;

    // Public inputs
    signal input Qx;
    signal input Qy;

    // Private inputs
    signal input hashed_claims[N];
    signal input r;
    signal input s;

    // Output
    signal output valid;


    var l2 = N \ hash_width;
    var rm = N % hash_width;

    var width = l2;
    if (rm > 0) {
        width += 1;
    }

    if (N <= hash_width) {
        width = N;
    }

    component top_h = Poseidon(width);
    component bot_h[width];

    if (N <= 16) {
        top_h.inputs <== hashed_claims;

    } else {

        for (var i = 0; i < l2; i++) {
            bot_h[i] = Poseidon(hash_width);

            for (var j = 0; j < hash_width; j++) {
                bot_h[i].inputs[j] <== hashed_claims[i * hash_width + j];
            }
            top_h.inputs[i] <== bot_h[i].out;
        }

        if (rm > 0) {
            bot_h[l2] = Poseidon(rm);

            for (var j = 0; j < rm; j++) {
                bot_h[l2].inputs[j] <== hashed_claims[l2 * hash_width + j];
            }
            top_h.inputs[l2] <== bot_h[l2].out;
        }
    }
    
    component ecdsa = ECDSA(64, 4);
    ecdsa.r <== r;
    ecdsa.s <== s;
    ecdsa.m <== top_h.out;
    ecdsa.Qx <== Qx;
    ecdsa.Qy <== Qy;

    valid <== ecdsa.valid;

}


// component main = VerifyCredentialSignature(256);