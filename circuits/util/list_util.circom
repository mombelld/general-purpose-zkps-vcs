pragma circom 2.1.2;

include "../../circomlib/circuits/comparators.circom";

/**
 * Selects an item from a list based on the given index.
 * Inspired by https://github.com/privacy-scaling-explorations/maci/blob/dev/packages/circuits/circom/trees/incrementalQuinaryTree.circom
 */
template ListSelector(N) {
    signal input list[N];
    signal input index;
    signal output selected;

    // Check that index is smaller than number of elements
    component lt = LessThan(128);
    lt.in[0] <== index;
    lt.in[1] <== N;
    lt.out === 1;

    var selectedElement[N];

    component eqs[N];

    for (var i = 0; i < N; i++) {
        var selector = IsEqual()([i, index]);
        selectedElement[i] = selector * list[i];
    }

    selected <== CalculateTotal(N)(selectedElement);
}

template CalculateTotal(N) {
    signal input list[N];
    signal output sum;

    signal sums[N];
    sums[0] <== list[0];

    for (var i = 1; i < N; i++) {
        sums[i] <== sums[i - 1] + list[i];
    }

    sum <== sums[N - 1];
}