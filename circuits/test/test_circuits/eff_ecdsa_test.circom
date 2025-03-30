pragma circom 2.1.2;

include "../../secp256k1/eff_ecdsa_membership/eff_ecdsa.circom";

template TestEffEcdsa() {
    signal input s;
    signal input Tx; // T = r^-1 * R
    signal input Ty;
    signal input Ux; // U = -(m * r^-1 * G)
    signal input Uy;
    signal input Qx;
    signal input Qy;

    component ecdsa = EfficientECDSA();
    ecdsa.s <== s;
    ecdsa.Tx <== Tx;
    ecdsa.Ty <== Ty;
    ecdsa.Ux <== Ux;
    ecdsa.Uy <== Uy;

    Qx === ecdsa.pubKeyX;
    Qy === ecdsa.pubKeyY;
}

component main = TestEffEcdsa();