pragma circom 2.1.2;

include "../circom-ecdsa-p256/p256.circom";
include "./precomp_mul.circom";
include "../secp256k1/eff_ecdsa_membership/modular_arithmetic/bigint.circom";
include "../../circomlib/circuits/comparators.circom";

// N = 43, K = 6
template FastP256Verify(N, K) {
    // Public inputs
    signal input Ux;
    signal input Uy;
    signal input powers_T[32][256][2][6];

    // Private inputs
    signal input Qx;
    signal input Qy;
    signal input s;

    // Outputs
    signal output valid;

    // Convert values to arrays
    component Ux_chunk = numToChunks(N, K);
    Ux_chunk.in <== Ux;

    component Uy_chunk = numToChunks(N, K);
    Uy_chunk.in <== Uy;

    component s_chunk = numToChunks(N, K);
    s_chunk.in <== s;

    // Perform verification
    // Compute s * T
    component sT = PrecompMul(N, K);
    sT.s <== s_chunk.out;
    sT.powers <== powers_T;

    // Compute R = sT + U
    component sT_U = P256AddUnequal(N, K);
    sT_U.a[0] <== sT.out[0];
    sT_U.a[1] <== sT.out[1];
    sT_U.b[0] <== Ux_chunk.out;
    sT_U.b[1] <== Uy_chunk.out;

    // Get R
    component Rx = chunksToNum(N, K);
    Rx.in <== sT_U.out[0];

    component Ry = chunksToNum(N, K);
    Ry.in <== sT_U.out[1];

    // Check R == Q
    component eqx = IsEqual();
    eqx.in[0] <== Rx.out;
    eqx.in[1] <== Qx;

    component eqy = IsEqual();
    eqy.in[0] <== Ry.out;
    eqy.in[1] <== Qy;

    valid <== eqx.out * eqy.out;

}

// component main = FastP256Verify(43, 6);