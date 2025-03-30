pragma circom 2.1.2;

include "../../circuits/cred_ver.circom";
include "../../circuits/status_list_check.circom";
include "../../circuits/poseidon/poseidon.circom";
include "../../circuits/util/ver_claim_membership.circom";
include "../../circomlib/circuits/comparators.circom";
include "../../circomlib/circuits/gates.circom";
include "../../circuits/secp256r1/fast_ecdsa_p256.circom";


template Proof(n_claims, sl_length) {
    // ---------------- Public inputs ----------------
    signal input exp_name;
    
    signal input status_list[sl_length];
    signal input status_list_uri_name;
    signal input status_list_uri_value[15];

    signal input status_list_idx_name;

    signal input iss_pk_x;
    signal input iss_pk_y;

    signal input now_timestamp;
    signal input date_offset_name;
    signal input date_offset_value;

    // Hardware binding public inputs
    signal input hb_ux;
    signal input hb_uy;
    signal input hb_powers[32][256][2][6];
    signal input cnf_jwk_x_name;
    signal input cnf_jwk_y_name;
    signal input hb_R_x;
    signal input hb_R_y;
    signal input hb_r;

    // ---------------- Private inputs ----------------
    signal input zk_r;
    signal input zk_s;

    signal input exp_value;
    signal input status_list_idx_value;

    signal input hashed_claims[n_claims];

    // Hardware binding private inputs
    signal input cnf_jwk_x_value;
    signal input cnf_jwk_y_value;
    signal input hb_s;

    // ---------------- Outputs ----------------
    signal output out[4];


    // Verify signature
    component ver = VerifyCredentialSignature(n_claims);
    ver.Qx <== iss_pk_x;
    ver.Qy <== iss_pk_y;
    ver.hashed_claims <== hashed_claims;
    ver.r <== zk_r;
    ver.s <== zk_s;
    signal valid_signature <== ver.valid;

    // Verify non-expiration
    component ver_exp = VerifyClaimMembership(n_claims, 4);
    ver_exp.hashed_claims <== hashed_claims;
    ver_exp.claim_name <== exp_name;
    ver_exp.claim_value <== exp_value;

    component exp_check = LessThan(128);
    exp_check.in[0] <== now_timestamp + date_offset_value;
    exp_check.in[1] <== exp_value;
    signal not_expired <== exp_check.out;

    // Verify non-revocation
    component ver_sl_uri = VerifyClaimMembershipString(n_claims, 6);
    ver_sl_uri.hashed_claims <== hashed_claims;
    ver_sl_uri.claim_name <== status_list_uri_name;
    ver_sl_uri.claim_value <== status_list_uri_value;

    component ver_sl_idx = VerifyClaimMembership(n_claims, 5);
    ver_sl_idx.hashed_claims <== hashed_claims;
    ver_sl_idx.claim_name <== status_list_idx_name;
    ver_sl_idx.claim_value <== status_list_idx_value;

    component status_check = StatusListCheck(1024, 256, 2);
    status_check.status_list <== status_list;
    status_check.status_list_idx <== status_list_idx_value;
    signal status <== status_check.status;

    component revoked_check = IsZero();
    revoked_check.in <== status;
    signal not_revoked <== revoked_check.out;

    // Verify hardware binding
    component ver_cnf_jwk_x = VerifyClaimMembership(n_claims, 7);
    ver_cnf_jwk_x.hashed_claims <== hashed_claims;
    ver_cnf_jwk_x.claim_name <== cnf_jwk_x_name;
    ver_cnf_jwk_x.claim_value <== cnf_jwk_x_value;

    component ver_cnf_jwk_y = VerifyClaimMembership(n_claims, 8);
    ver_cnf_jwk_y.hashed_claims <== hashed_claims;
    ver_cnf_jwk_y.claim_name <== cnf_jwk_y_name;
    ver_cnf_jwk_y.claim_value <== cnf_jwk_y_value;

    component hb_check = FastP256Verify(43, 6);
    hb_check.Ux <== hb_ux;
    hb_check.Uy <== hb_uy;
    hb_check.powers_T <== hb_powers;
    hb_check.Qx <== cnf_jwk_x_value;
    hb_check.Qy <== cnf_jwk_y_value;
    hb_check.s <== hb_s;
    signal valid_hb <== hb_check.valid;

    component m_and = MultiAND(4);
    m_and.in[0] <== valid_signature;
    m_and.in[1] <== not_expired;
    m_and.in[2] <== not_revoked;
    m_and.in[3] <== valid_hb;
    out[0] <== m_and.out;
    out[1] <== hb_r;
    out[2] <== hb_R_x;
    out[3] <== hb_R_y;


}

component main {public [exp_name, status_list, status_list_uri_name, status_list_uri_value, status_list_idx_name, iss_pk_x, iss_pk_y, now_timestamp, date_offset_name, date_offset_value, hb_ux, hb_uy, hb_powers, cnf_jwk_x_name, cnf_jwk_y_name]} = Proof(22, 1024);