pragma circom 2.1.2;

include "./cred_ver.circom";
include "./status_list_check.circom";
include "./poseidon/poseidon.circom";
include "./util/ver_claim_membership.circom";
include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/gates.circom";

/**
 * Verify signature, non-expiration and non-revocation
 */
template CredentialValidityCheck(n_claims, sl_length) {
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

    // ---------------- Private inputs ----------------
    signal input zk_r;
    signal input zk_s;

    signal input exp_value;
    signal input status_list_idx_value;


    signal input hashed_claims[n_claims];

    // ---------------- Outputs ----------------
    signal output out;

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

    component ver_date_offset = VerifyClaimMembership(n_claims, 10);
    ver_date_offset.hashed_claims <== hashed_claims;
    ver_date_offset.claim_name <== date_offset_name;
    ver_date_offset.claim_value <== date_offset_value;

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

    component m_and = MultiAND(3);
    m_and.in[0] <== valid_signature;
    m_and.in[1] <== not_expired;
    m_and.in[2] <== not_revoked;

    out <== m_and.out;
}

/**
 * Verify signature, non-expiration and non-revocation
 */
template CredentialValidityCheckNoStatus(n_claims, sl_length) {
    // ---------------- Public inputs ----------------
    signal input exp_name;
    signal input iss_pk_x;
    signal input iss_pk_y;
    signal input now_timestamp;
    signal input date_offset_name;
    signal input date_offset_value;

    // ---------------- Private inputs ----------------
    // > Identity credential
    signal input zk_r;
    signal input zk_s;
    signal input exp_value;
    signal input hashed_claims[n_claims];

    // ---------------- Outputs ----------------
    signal output out;

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

    component ver_date_offset = VerifyClaimMembership(n_claims, 10);
    ver_date_offset.hashed_claims <== hashed_claims;
    ver_date_offset.claim_name <== date_offset_name;
    ver_date_offset.claim_value <== date_offset_value;

    component exp_check = LessThan(128);
    exp_check.in[0] <== now_timestamp + date_offset_value;
    exp_check.in[1] <== exp_value;
    signal not_expired <== exp_check.out;


    component m_and = MultiAND(2);
    m_and.in[0] <== valid_signature;
    m_and.in[1] <== not_expired;

    out <== m_and.out;
}