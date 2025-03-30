package ch.admin.bj.swiyu.issuer.oid4vci.zk;

import ch.admin.bj.swiyu.issuer.oid4vci.zk.PoseidonConstants;
import java.math.BigInteger;


public class Poseidon {

    private static final BigInteger p = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    public static final int securityLevel = 128;
    public static final int alpha = 5;
    private static final int[] nPartialRounds = {56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68};
    

    private static BigInteger sbox(BigInteger n) {
        return n.pow(alpha).mod(p);
    }

    private static void matMul(BigInteger[] state, BigInteger[][] mds, int t) {
        int n = state.length;
        BigInteger[] tmp = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            tmp[i] = new BigInteger(state[i].toByteArray());
        }

        for (int i = 0; i < t; i++) {
            BigInteger acc = BigInteger.ZERO;
            for (int j = 0; j < t; j++) {
                BigInteger mul = tmp[j].multiply(mds[i][j]).mod(p);
                acc = acc.add(mul).mod(p);
            }

            state[i] = acc;
        }

    }

    private static int fullRound(BigInteger[] state, BigInteger[] rc, BigInteger[][] mds, int t, int nRounds, int rcCounter) {
        for (int r = 0; r < nRounds; r++) {
            for (int i = 0; i < t; i++) {
                state[i] = state[i].add(rc[rcCounter]).mod(p);
                rcCounter++;

                state[i] = sbox(state[i]);
            }

            matMul(state, mds, t);
        }

        return rcCounter;
    }

    private static int partialRound(BigInteger[] state, BigInteger[] rc, BigInteger[][] mds, int t, int nRounds, int rcCounter) {
        for (int r = 0; r < nRounds; r++) {
            for (int i = 0; i < t; i++) {
                state[i] = state[i].add(rc[rcCounter]).mod(p);
                rcCounter++;
            }
            
            state[0] = sbox(state[0]);
            matMul(state, mds, t);
        }

        return rcCounter;
    }

    public BigInteger hash(BigInteger[] input) {
        int n = input.length;
        int t = n + 1;

        int nFRounds = 8;
        int nFRoundsHalf = (int) nFRounds / 2;
        int nPRounds = nPartialRounds[t - 2];

        BigInteger[] state = new BigInteger[t];
        state[n] = BigInteger.ZERO;

        for (int i = 0; i < n; i++) {
            state[i] = new BigInteger(input[i].mod(p).toByteArray());
        }

        int rcCounter = 0;
        BigInteger[] rc = PoseidonConstants.getRc(t);
        BigInteger[][] mds = PoseidonConstants.getMds(t);

        rcCounter = fullRound(state, rc, mds, t, nFRoundsHalf, rcCounter);

        rcCounter = partialRound(state, rc, mds, t, nPRounds, rcCounter);
        
        rcCounter = fullRound(state, rc, mds, t, nFRoundsHalf, rcCounter);

        return state[1];
    }
}