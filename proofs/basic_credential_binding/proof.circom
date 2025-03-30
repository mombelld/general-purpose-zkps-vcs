pragma circom 2.1.2;

include "../../circuits/cred_ver.circom";
include "../../circuits/credential_validity_check.circom";
include "../../circuits/status_list_check.circom";
include "../../circuits/poseidon/poseidon.circom";
include "../../circuits/util/ver_claim_membership.circom";
include "../../circuits/util/string_util.circom";
include "../../circomlib/circuits/comparators.circom";
include "../../circomlib/circuits/gates.circom";

template Proof(identity_n_claims, diploma_n_claims, sl_length) {
    // ---------------- Public inputs ----------------
    // Constants
    signal input iss_pk_x;
    signal input iss_pk_y;
    signal input over_18;
    signal input identity_vct_comp[15];
    signal input diploma_vct_comp[15];
    signal input zuerich_string[15];
    signal input ethz_string[15];
    signal input epfl_string[15];
    signal input ch_string[15];
    signal input now_timestamp;

    // > Identity credential
    signal input identity_vct_name;
    signal input identity_exp_name;
    signal input identity_cred_bind_name;
    
    signal input identity_status_list[sl_length];
    signal input identity_status_list_uri_name;
    signal input identity_status_list_uri_value[15];
    signal input identity_status_list_idx_name;

    signal input identity_date_offset_name;
    signal input identity_date_offset_value;
    signal input identity_birthdate_name;
    signal input identity_locality_name;
    signal input identity_nationality_name;

    // > Diploma credential
    signal input diploma_vct_name;
    signal input diploma_exp_name;
    signal input diploma_cred_bind_name;
    
    signal input diploma_date_offset_name;
    signal input diploma_date_offset_value;
    signal input diploma_university_name;


    // ---------------- Private inputs ----------------
    // > Identity credential
    signal input identity_zk_r;
    signal input identity_zk_s;
    signal input identity_vct_value[15];
    signal input identity_exp_value;
    signal input identity_cred_bind_value[15];
    signal input identity_status_list_idx_value;
    signal input identity_birthdate_value;
    signal input identity_locality_value[15];
    signal input identity_nationality_value[15];

    signal input identity_hashed_claims[identity_n_claims];

    // > Diploma credential
    signal input diploma_zk_r;
    signal input diploma_zk_s;

    signal input diploma_vct_value[15];
    signal input diploma_exp_value;
    signal input diploma_cred_bind_value[15];

    signal input diploma_university_value[15];
    signal input diploma_hashed_claims[diploma_n_claims];


    // ---------------- Outputs ----------------
    signal output out;

    component identity_validity_check = CredentialValidityCheck(identity_n_claims, sl_length);
    identity_validity_check.exp_name <== identity_exp_name;
    identity_validity_check.status_list <== identity_status_list;
    identity_validity_check.status_list_uri_name <== identity_status_list_uri_name;
    identity_validity_check.status_list_uri_value <== identity_status_list_uri_value;
    identity_validity_check.status_list_idx_name <== identity_status_list_idx_name;
    identity_validity_check.iss_pk_x <== iss_pk_x;
    identity_validity_check.iss_pk_y <== iss_pk_y;
    identity_validity_check.now_timestamp <== now_timestamp;
    identity_validity_check.date_offset_name <== identity_date_offset_name;
    identity_validity_check.date_offset_value <== identity_date_offset_value;
    identity_validity_check.zk_r <== identity_zk_r;
    identity_validity_check.zk_s <== identity_zk_s;
    identity_validity_check.exp_value <== identity_exp_value;
    identity_validity_check.status_list_idx_value <== identity_status_list_idx_value;
    identity_validity_check.hashed_claims <== identity_hashed_claims;
    signal identity_valid <== identity_validity_check.out;

    component diploma_validity_check = CredentialValidityCheckNoStatus(diploma_n_claims, sl_length);
    diploma_validity_check.exp_name <== diploma_exp_name;
    diploma_validity_check.iss_pk_x <== iss_pk_x;
    diploma_validity_check.iss_pk_y <== iss_pk_y;
    diploma_validity_check.now_timestamp <== now_timestamp;
    diploma_validity_check.date_offset_name <== diploma_date_offset_name;
    diploma_validity_check.date_offset_value <== diploma_date_offset_value;
    diploma_validity_check.zk_r <== diploma_zk_r;
    diploma_validity_check.zk_s <== diploma_zk_s;
    diploma_validity_check.exp_value <== diploma_exp_value;
    diploma_validity_check.hashed_claims <== diploma_hashed_claims;
    signal diploma_valid <== diploma_validity_check.out;

    // Check vcts
    component identity_ver_vct = VerifyClaimMembershipString(identity_n_claims, 1);
    identity_ver_vct.hashed_claims <== identity_hashed_claims;
    identity_ver_vct.claim_name <== identity_vct_name;
    identity_ver_vct.claim_value <== identity_vct_value;

    component identity_vct_check = StringEquals(15);
    identity_vct_check.a <== identity_vct_value;
    identity_vct_check.b <== identity_vct_comp;
    1 === identity_vct_check.out;

    component diploma_ver_vct = VerifyClaimMembershipString(diploma_n_claims, 1);
    diploma_ver_vct.hashed_claims <== diploma_hashed_claims;
    diploma_ver_vct.claim_name <== diploma_vct_name;
    diploma_ver_vct.claim_value <== diploma_vct_value;

    component diploma_vct_check = StringEquals(15);
    diploma_vct_check.a <== diploma_vct_value;
    diploma_vct_check.b <== diploma_vct_comp;
    1 === diploma_vct_check.out;

    // Check binding
    component identity_ver_cred_bind = VerifyClaimMembershipString(identity_n_claims, 9);
    identity_ver_cred_bind.hashed_claims <== identity_hashed_claims;
    identity_ver_cred_bind.claim_name <== identity_cred_bind_name;
    identity_ver_cred_bind.claim_value <== identity_cred_bind_value;

    component diploma_ver_cred_bind = VerifyClaimMembershipString(diploma_n_claims, 9);
    diploma_ver_cred_bind.hashed_claims <== diploma_hashed_claims;
    diploma_ver_cred_bind.claim_name <== diploma_cred_bind_name;
    diploma_ver_cred_bind.claim_value <== diploma_cred_bind_value;

    component enforce_binding = StringEquals(15);
    enforce_binding.a <== identity_cred_bind_value;
    enforce_binding.b <== diploma_cred_bind_value;
    1 === enforce_binding.out;

    // Verify over 18
    component ver_birthdate = VerifyClaimMembership(identity_n_claims, 21);
    ver_birthdate.hashed_claims <== identity_hashed_claims;
    ver_birthdate.claim_name <== identity_birthdate_name;
    ver_birthdate.claim_value <== identity_birthdate_value;

    component age_check = LessThan(128);
    age_check.in[0] <== identity_birthdate_value;
    age_check.in[1] <== over_18 + identity_date_offset_value;
    signal age_over_18 <== age_check.out;

    // Check university is ETHZ or EPFL
    component diploma_ver_university = VerifyClaimMembershipString(diploma_n_claims, 15);
    diploma_ver_university.hashed_claims <== diploma_hashed_claims;
    diploma_ver_university.claim_name <== diploma_university_name;
    diploma_ver_university.claim_value <== diploma_university_value;

    component ethz_check = StringEquals(15);
    ethz_check.a <== ethz_string;
    ethz_check.b <== diploma_university_value;

    component epfl_check = StringEquals(15);
    epfl_check.a <== epfl_string;
    epfl_check.b <== diploma_university_value;

    signal university_valid <== ethz_check.out + epfl_check.out;

    // Check locality is Zürich
    component identity_ver_locality = VerifyClaimMembershipString(identity_n_claims, 17);
    identity_ver_locality.hashed_claims <== identity_hashed_claims;
    identity_ver_locality.claim_name <== identity_locality_name;
    identity_ver_locality.claim_value <== identity_locality_value;

    component zuerich_check = StringEquals(15);
    zuerich_check.a <== zuerich_string;
    zuerich_check.b <== identity_locality_value;
    signal locality_valid <== zuerich_check.out;

    // Check nationality is CH
    component identity_ver_nationality = VerifyClaimMembershipString(identity_n_claims, 15);
    identity_ver_nationality.hashed_claims <== identity_hashed_claims;
    identity_ver_nationality.claim_name <== identity_nationality_name;
    identity_ver_nationality.claim_value <== identity_nationality_value;

    component ch_check = StringEquals(15);
    ch_check.a <== ch_string;
    ch_check.b <== identity_nationality_value;
    signal nationality_valid <== ch_check.out;

    component m_and = MultiAND(5);
    m_and.in[0] <== identity_valid * diploma_valid;
    m_and.in[1] <== age_over_18;
    m_and.in[2] <== university_valid;
    m_and.in[3] <== locality_valid;
    m_and.in[4] <== nationality_valid;

    out <== m_and.out;

}

component main {public [identity_vct_name, identity_exp_name, identity_cred_bind_name, identity_status_list, identity_status_list_uri_name, identity_status_list_uri_value, identity_status_list_idx_name, iss_pk_x, iss_pk_y, now_timestamp, identity_date_offset_name, identity_date_offset_value, identity_birthdate_name, identity_locality_name, over_18, identity_vct_comp, zuerich_string, diploma_vct_name, diploma_exp_name, diploma_cred_bind_name, diploma_date_offset_name, diploma_date_offset_value, diploma_university_name, diploma_vct_comp, ethz_string, epfl_string]} = Proof(22, 18, 1024);