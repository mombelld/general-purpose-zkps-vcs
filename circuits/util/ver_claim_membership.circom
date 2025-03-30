pragma circom 2.1.2;

include "../poseidon/poseidon.circom";

template VerifyClaimMembership(n_claims, index) {
    signal input hashed_claims[n_claims];
    signal input claim_name;
    signal input claim_value;

    component ph = Poseidon(2);
    ph.inputs[0] <== claim_name;
    ph.inputs[1] <== claim_value;
    ph.out === hashed_claims[index];
}

template VerifyClaimMembershipString(n_claims, index) {
    signal input hashed_claims[n_claims];
    signal input claim_name;
    signal input claim_value[15];

    component ph = Poseidon(16);
    ph.inputs[0] <== claim_name;

    for (var i = 1; i < 16; i++) {
        ph.inputs[i] <== claim_value[i - 1];
    }

    ph.out === hashed_claims[index];
}

// component main = VerifyClaimMembershipString(12, 1);