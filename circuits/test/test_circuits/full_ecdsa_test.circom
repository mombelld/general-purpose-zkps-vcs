pragma circom 2.1.2;

include "../../secp256k1/eff_ecdsa_membership/ecdsa.circom";

template TestFullEcdsa() {
    signal input r;
    signal input s;
    signal input m;
    signal input Qx;
    signal input Qy;

    component ecdsa = ECDSA(64, 4);
    ecdsa.r <== r;
    ecdsa.s <== s;
    ecdsa.m <== m;
    ecdsa.Qx <== Qx;
    ecdsa.Qy <== Qy;

    ecdsa.valid === 1;
}

component main = TestFullEcdsa();