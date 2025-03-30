import poseidon_constants

N_PARTIAL_ROUNDS = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
ALPHA = 5
SECURITY_LEVEL = 128

def mat_mul(state, mds, t):
    n = len(state)
    out = [0 for _ in range(n)]

    for i in range(t):
        acc = 0
        for j in range(t):
            mul = (state[j] * mds[i][j]) % P
            acc = (acc + mul) % P

        out[i] = acc

    return out

def full_round(state, rc, mds, t, n_rounds, rc_counter):
    for r in range(n_rounds):
        for i in range(t):
            state[i] = (state[i] + rc[rc_counter]) % P
            rc_counter += 1

            state[i] = pow(state[i], ALPHA, P)

        state = mat_mul(state, mds, t)

    return rc_counter, state

def partial_round(state, rc, mds, t, n_rounds, rc_counter):
    for r in range(n_rounds):
        for i in range(t):
            state[i] = (state[i] + rc[rc_counter]) % P
            rc_counter += 1

        state[0] = pow(state[0], ALPHA, P)
        state = mat_mul(state, mds, t)
    
    return rc_counter, state

def hash(input_list: list):
    n = len(input_list)
    t = n + 1

    n_frounds = 8
    n_frounds_half = n_frounds // 2
    n_prounds = N_PARTIAL_ROUNDS[t - 2]

    state = [0 for _ in range(t)]
    for i, inp in enumerate(input_list):
        state[i] = inp % P
    rc_counter = 0

    rc = poseidon_constants.ROUND_KEYS(t)
    mds = poseidon_constants.MDS_MATRIX(t)

    rc_counter, state = full_round(state, rc, mds, t, n_frounds_half, rc_counter)
    rc_counter, state = partial_round(state, rc, mds, t, n_prounds, rc_counter)
    rc_counter, state = full_round(state, rc, mds, t, n_frounds_half, rc_counter)

    return state[1]