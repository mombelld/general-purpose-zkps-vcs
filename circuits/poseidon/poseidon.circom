pragma circom 2.1.2;

include "./poseidon_constants.circom";

template SBox() {
    signal input in;
    signal output out;

    signal inDouble <== in * in;
    signal inQuadruple <== inDouble * inDouble;
    

    out <== inQuadruple * in;
}

template MatrixMul(t) {
    signal input state[t];
    signal output out[t];
    var mds_matrix[t][t] = MDS_MATRIX(t);

    for (var i = 0; i < t; i++) {
        var tmp = 0;
        for (var j = 0; j < t; j++) {
            tmp += state[j] * mds_matrix[i][j];
        }
        out[i] <== tmp;
    }
}

template AddRoundConst(pos, n, t) {
    signal input state[t];
    signal output out[t]; 
    var round_keys[n] = ROUND_KEYS(t);

    for (var i = 0; i < t; i++) {
        out[i] <== state[i] + round_keys[pos + i];
    }
}

template FullRound(pos, n, t) {
    signal input state[t];
    signal output out[t];
    component constAdded = AddRoundConst(pos, n, t);
    for (var i = 0; i < t; i++) {
        constAdded.state[i] <== state[i];
    }


    component sBoxes[t];
    for (var i = 0; i < t; i++) {
        sBoxes[i] = SBox();
        sBoxes[i].in <== constAdded.out[i];
    }

    component matrixMul = MatrixMul(t);
    for (var i = 0; i < t; i++) {
        matrixMul.state[i] <== sBoxes[i].out;
    }

    for (var i = 0; i < t; i++) {
        out[i] <== matrixMul.out[i];
    }
}

template PartialRound(pos, n, t) {
    signal input state[t];
    signal output out[t];

    component constAdded = AddRoundConst(pos, n, t);
    for (var i = 0; i < t; i++) {
        constAdded.state[i] <== state[i];
    }

    component sBox = SBox();
    sBox.in <== constAdded.out[0];

    component matrixMul = MatrixMul(t);
    for (var i = 0; i < t; i++) {
        if (i == 0) {
            matrixMul.state[i] <== sBox.out;
        } else {
            matrixMul.state[i] <== constAdded.out[i];
        }
    }

    for (var i = 0; i < t; i++) {
        out[i] <== matrixMul.out[i];
    }
}

template Poseidon(numInputs) {
    signal input inputs[numInputs];
    signal output out;

    var N_ROUNDS_P[16] = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
    var t = numInputs + 1;
    var numFullRounds = 8;
    var numFullRoundsHalf = 4;
    var numPartialRounds = N_ROUNDS_P[t - 2];
    var n = t * (numFullRounds + numPartialRounds);

    var stateIndex = 0;
    
    signal initState[t];

    // Note: padding may need to be appended or prepended depending on what the external implementation does, also it may be different from 0 in some cases
    initState[numInputs] <== 0;

    for (var i = 0; i < numInputs; i++) {
        initState[i] <== inputs[i];
    }

    component fRoundsFirst[numFullRoundsHalf];
    for (var j = 0; j < numFullRoundsHalf; j++) {
        fRoundsFirst[j] = FullRound(stateIndex * t, n, t);
        if (j == 0) {
            for (var i = 0; i < t; i++) {
                fRoundsFirst[j].state[i] <== initState[i];
            }
        } else {
            for (var i = 0; i < t; i++) {
                fRoundsFirst[j].state[i] <== fRoundsFirst[j - 1].out[i];
            }
        }
        stateIndex++;
    }


    component pRounds[numPartialRounds];
    for (var j = 0; j < numPartialRounds; j++) {
        pRounds[j] = PartialRound(stateIndex * t, n, t);
        if (j == 0) {
            for (var i = 0; i < t; i++) {
                pRounds[j].state[i] <== fRoundsFirst[numFullRoundsHalf - 1].out[i];
            }
        } else {
            for (var i = 0; i < t; i++) {
                pRounds[j].state[i] <== pRounds[j - 1].out[i];
            }
        }
        stateIndex++;
    }

    component fRoundsLast[numFullRoundsHalf];
    for (var j = 0; j < numFullRoundsHalf; j++) {
        fRoundsLast[j] = FullRound(stateIndex * t, n, t);
        if (j == 0) {
            for (var i = 0; i < t; i++) {
                fRoundsLast[j].state[i] <== pRounds[numPartialRounds - 1].out[i];
            }
        } else {
            for (var i = 0; i < t; i++) {
                fRoundsLast[j].state[i] <== fRoundsLast[j - 1].out[i];
            }
        }
        stateIndex++;
    }

    out <== fRoundsLast[numFullRoundsHalf-1].out[1];
}
