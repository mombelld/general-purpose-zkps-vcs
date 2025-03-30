pragma circom 2.1.2;


include "../../circomlib/circuits/comparators.circom";
include "../../circomlib/circuits/gates.circom";

template StringEquals(len) {
    signal input a[len];
    signal input b[len];

    signal output out;

    component eqs[len];
    component m_and = MultiAND(len);

    for (var i = 0; i < len; i++) {
        eqs[i] = IsEqual();
        eqs[i].in[0] <== a[i];
        eqs[i].in[1] <== b[i];

        m_and.in[i] <== eqs[i].out;
    }

    out <== m_and.out;
}