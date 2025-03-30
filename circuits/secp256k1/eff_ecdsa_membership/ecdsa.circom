pragma circom 2.1.2;

include "./secp256k1/mul.circom";
include "../../../circomlib/circuits/bitify.circom";
include "../../../circomlib/circuits/comparators.circom";
include "./modular_arithmetic/bigint.circom";
include "./modular_arithmetic/bigint_functions.circom";

function Gx() {
    return 55066263022277343669578718895168534326250603453777594175500187360389116729240;
}

function Gy() {
    return 32670510020758816978083085130507043184471273380659243275938904335757337482424;
}

function order() {
    return 115792089237316195423570985008687907852837564279074904382605163141518161494337;
}

/**
 *  ECDSA
 *  ====================
 *  Verifies inputted ECDSA signature.
 */
template ECDSA(n, k) {
    // n: size of chunks in bits
    // k: number of chunks
    signal input r;
    signal input s;
    signal input m;
    signal input Qx;
    signal input Qy;

    signal output valid;

    // Chunk scalars
    component s_chunk = numToChunks(n, k);
    s_chunk.in <== s;

    component r_chunk = numToChunks(n, k);
    r_chunk.in <== r;

    component m_chunk = numToChunks(n, k);
    m_chunk.in <== m;

    component order_chunk = numToChunks(n, k);
    order_chunk.in <== order();

    // compute multiplicative inverse of s mod order
    component sinv =  inv(n, k);
    sinv.s <== s_chunk.out;
    sinv.order <== order_chunk.out;

     // compute u1 =  (m * sinv) mod order
    component u1_chunk = BigMultModPB(n, k);
    u1_chunk.a <== sinv.sinv;
    u1_chunk.b <== m_chunk.out;
    u1_chunk.p <== order_chunk.out;

    component u1 = chunksToNum(n, k);
    u1.in <== u1_chunk.out;

    // compute u2 = (r * sinv) mod order
    component u2_chunk = BigMultModPB(n, k);
    u2_chunk.a <== sinv.sinv;
    u2_chunk.b <== r_chunk.out;
    u2_chunk.p <== order_chunk.out;


    component u2 = chunksToNum(n, k);
    u2.in <== u2_chunk.out;

    // u1 * G
    component mul0 = Secp256k1Mul();
    mul0.scalar <== u1.out;
    mul0.xP <== Gx();
    mul0.yP <== Gy();

    // u2 * Q
    component mul1 = Secp256k1Mul();
    mul1.scalar <== u2.out;
    mul1.xP <== Qx;
    mul1.yP <== Qy;

    // R = u1 * G + u2 * Q
    component R = Secp256k1AddComplete();
    R.xP <== mul0.outX;
    R.yP <== mul0.outY;
    R.xQ <== mul1.outX;
    R.yQ <== mul1.outY;

    component eq = IsEqual();
    eq.in[0] <== R.outX;
    eq.in[1] <== r;

    valid <== eq.out;
}

template inv(n, k) {
    signal input s[k];
    signal input order[k];
    signal output sinv[k];

    var sinv_comp[100] = mod_invB(n, k, s, order);

    component sinv_range_checks[k];
    for (var idx = 0; idx < k; idx++) {
        sinv[idx] <-- sinv_comp[idx];
        sinv_range_checks[idx] = Num2Bits(n);
        sinv_range_checks[idx].in <== sinv[idx];

    }

    component sinv_check = BigMultModPB(n, k);
    for (var idx = 0; idx < k; idx++) {
        sinv_check.a[idx] <== sinv[idx];
        sinv_check.b[idx] <== s[idx];
        sinv_check.p[idx] <== order[idx];

    }

    for (var idx = 0; idx < k; idx++) {
        if (idx > 0) {
            sinv_check.out[idx] === 0;

        }
        if (idx == 0) {
            sinv_check.out[idx] === 1;

        }
    }
}
