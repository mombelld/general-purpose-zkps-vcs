pragma circom 2.1.2;

include "../../circuits/cred_ver.circom";
include "../../circuits/credential_validity_check.circom";
include "../../circuits/status_list_check.circom";
include "../../circuits/poseidon/poseidon.circom";
include "../../circuits/util/ver_claim_membership.circom";
include "../../circuits/util/string_util.circom";
include "../../circomlib/circuits/comparators.circom";
include "../../circomlib/circuits/gates.circom";

/**
 * Out = age > 18 & (uni = ETHZ | uni = EPFL) & degree = Computer Science MSc &
 *      SUM(years in rl s.t. rl.profession = Security Engineer | rl.profession = Security Analyst ) > 5
 */

template Proof(identity_n_claims, diploma_n_claims, rl_n_claims, sl_length) {
    // ---------------- Public inputs ----------------
    // Constants
    signal input iss_pk_x;
    signal input iss_pk_y;
    signal input over_18;
    signal input identity_vct_comp[15];
    signal input diploma_vct_comp[15];
    signal input rl_vct_comp[15];
    signal input ethz_string[15];
    signal input epfl_string[15];
    signal input degree_string[15];
    signal input sec_enc_string[15];
    signal input sec_analyst_string[15];
    signal input five_years;
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

    // > Diploma credential
    signal input diploma_vct_name;
    signal input diploma_exp_name;
    signal input diploma_cred_bind_name;
    
    signal input diploma_date_offset_name;
    signal input diploma_date_offset_value;
    signal input diploma_university_name;
    signal input diploma_degree_name;

    // > Reference letter 0
    signal input rl0_vct_name;
    signal input rl0_exp_name;
    signal input rl0_cred_bind_name;
    
    signal input rl0_date_offset_name;
    signal input rl0_date_offset_value;
    signal input rl0_profession_name;
    signal input rl0_start_date_name;
    signal input rl0_end_date_name;

    // > Reference letter 1
    signal input rl1_vct_name;
    signal input rl1_exp_name;
    signal input rl1_cred_bind_name;

    signal input rl1_date_offset_name;
    signal input rl1_date_offset_value;
    signal input rl1_profession_name;
    signal input rl1_start_date_name;
    signal input rl1_end_date_name;

    // > Reference letter 2
    signal input rl2_vct_name;
    signal input rl2_exp_name;
    signal input rl2_cred_bind_name;
    
    signal input rl2_date_offset_name;
    signal input rl2_date_offset_value;
    signal input rl2_profession_name;
    signal input rl2_start_date_name;
    signal input rl2_end_date_name;


    // ---------------- Private inputs ----------------
    // > Identity credential
    signal input identity_zk_r;
    signal input identity_zk_s;
    signal input identity_vct_value[15];
    signal input identity_exp_value;
    signal input identity_cred_bind_value[15];
    signal input identity_status_list_idx_value;
    signal input identity_birthdate_value;

    signal input identity_hashed_claims[identity_n_claims];

    // > Diploma credential
    signal input diploma_zk_r;
    signal input diploma_zk_s;

    signal input diploma_vct_value[15];
    signal input diploma_exp_value;
    signal input diploma_cred_bind_value[15];
    signal input diploma_university_value[15];
    signal input diploma_degree_value[15];
    signal input diploma_hashed_claims[diploma_n_claims];

    // > Reference letter 0
    signal input rl0_zk_r;
    signal input rl0_zk_s;

    signal input rl0_vct_value[15];
    signal input rl0_exp_value;
    signal input rl0_cred_bind_value[15];
    signal input rl0_profession_value[15];
    signal input rl0_start_date_value;
    signal input rl0_end_date_value;
    signal input rl0_hashed_claims[rl_n_claims];

    // > Reference letter 1
    signal input rl1_zk_r;
    signal input rl1_zk_s;

    signal input rl1_vct_value[15];
    signal input rl1_exp_value;
    signal input rl1_cred_bind_value[15];
    signal input rl1_profession_value[15];
    signal input rl1_start_date_value;
    signal input rl1_end_date_value;
    signal input rl1_hashed_claims[rl_n_claims];

    // > Reference letter 2
    signal input rl2_zk_r;
    signal input rl2_zk_s;

    signal input rl2_vct_value[15];
    signal input rl2_exp_value;
    signal input rl2_cred_bind_value[15];
    signal input rl2_profession_value[15];
    signal input rl2_start_date_value;
    signal input rl2_end_date_value;
    signal input rl2_hashed_claims[rl_n_claims];


    // ---------------- Outputs ----------------
    signal output out;

    // Check validity of credentials
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

    component rl0_validity_check = CredentialValidityCheckNoStatus(rl_n_claims, sl_length);
    rl0_validity_check.exp_name <== rl0_exp_name;
    rl0_validity_check.iss_pk_x <== iss_pk_x;
    rl0_validity_check.iss_pk_y <== iss_pk_y;
    rl0_validity_check.now_timestamp <== now_timestamp;
    rl0_validity_check.date_offset_name <== rl0_date_offset_name;
    rl0_validity_check.date_offset_value <== rl0_date_offset_value;
    rl0_validity_check.zk_r <== rl0_zk_r;
    rl0_validity_check.zk_s <== rl0_zk_s;
    rl0_validity_check.exp_value <== rl0_exp_value;
    rl0_validity_check.hashed_claims <== rl0_hashed_claims;
    signal rl0_valid <== rl0_validity_check.out;

    component rl1_validity_check = CredentialValidityCheckNoStatus(rl_n_claims, sl_length);
    rl1_validity_check.exp_name <== rl1_exp_name;
    rl1_validity_check.iss_pk_x <== iss_pk_x;
    rl1_validity_check.iss_pk_y <== iss_pk_y;
    rl1_validity_check.now_timestamp <== now_timestamp;
    rl1_validity_check.date_offset_name <== rl1_date_offset_name;
    rl1_validity_check.date_offset_value <== rl1_date_offset_value;
    rl1_validity_check.zk_r <== rl1_zk_r;
    rl1_validity_check.zk_s <== rl1_zk_s;
    rl1_validity_check.exp_value <== rl1_exp_value;
    rl1_validity_check.hashed_claims <== rl1_hashed_claims;
    signal rl1_valid <== rl1_validity_check.out;

    component rl2_validity_check = CredentialValidityCheckNoStatus(rl_n_claims, sl_length);
    rl2_validity_check.exp_name <== rl2_exp_name;
    rl2_validity_check.iss_pk_x <== iss_pk_x;
    rl2_validity_check.iss_pk_y <== iss_pk_y;
    rl2_validity_check.now_timestamp <== now_timestamp;
    rl2_validity_check.date_offset_name <== rl2_date_offset_name;
    rl2_validity_check.date_offset_value <== rl2_date_offset_value;
    rl2_validity_check.zk_r <== rl2_zk_r;
    rl2_validity_check.zk_s <== rl2_zk_s;
    rl2_validity_check.exp_value <== rl2_exp_value;
    rl2_validity_check.hashed_claims <== rl2_hashed_claims;
    signal rl2_valid <== rl2_validity_check.out;

    component valids = MultiAND(5);
    valids.in[0] <== identity_valid;
    valids.in[1] <== diploma_valid;
    valids.in[2] <== rl0_valid;
    valids.in[3] <== rl1_valid;
    valids.in[4] <== rl2_valid;
    signal all_creds_valid <== valids.out;

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

    component rl0_ver_vct = VerifyClaimMembershipString(rl_n_claims, 1);
    rl0_ver_vct.hashed_claims <== rl0_hashed_claims;
    rl0_ver_vct.claim_name <== rl0_vct_name;
    rl0_ver_vct.claim_value <== rl0_vct_value;
    
    component rl0_vct_check = StringEquals(15);
    rl0_vct_check.a <== rl0_vct_value;
    rl0_vct_check.b <== rl_vct_comp;
    1 === rl0_vct_check.out;

    component rl1_ver_vct = VerifyClaimMembershipString(rl_n_claims, 1);
    rl1_ver_vct.hashed_claims <== rl1_hashed_claims;
    rl1_ver_vct.claim_name <== rl1_vct_name;
    rl1_ver_vct.claim_value <== rl1_vct_value;
    
    component rl1_vct_check = StringEquals(15);
    rl1_vct_check.a <== rl1_vct_value;
    rl1_vct_check.b <== rl_vct_comp;
    1 === rl1_vct_check.out;

    component rl2_ver_vct = VerifyClaimMembershipString(rl_n_claims, 1);
    rl2_ver_vct.hashed_claims <== rl2_hashed_claims;
    rl2_ver_vct.claim_name <== rl2_vct_name;
    rl2_ver_vct.claim_value <== rl2_vct_value;
    
    component rl2_vct_check = StringEquals(15);
    rl2_vct_check.a <== rl2_vct_value;
    rl2_vct_check.b <== rl_vct_comp;
    1 === rl2_vct_check.out;

    // Check binding
    component identity_ver_cred_bind = VerifyClaimMembershipString(identity_n_claims, 9);
    identity_ver_cred_bind.hashed_claims <== identity_hashed_claims;
    identity_ver_cred_bind.claim_name <== identity_cred_bind_name;
    identity_ver_cred_bind.claim_value <== identity_cred_bind_value;

    component diploma_ver_cred_bind = VerifyClaimMembershipString(diploma_n_claims, 9);
    diploma_ver_cred_bind.hashed_claims <== diploma_hashed_claims;
    diploma_ver_cred_bind.claim_name <== diploma_cred_bind_name;
    diploma_ver_cred_bind.claim_value <== diploma_cred_bind_value;

    component rl0_ver_cred_bind = VerifyClaimMembershipString(rl_n_claims, 9);
    rl0_ver_cred_bind.hashed_claims <== rl0_hashed_claims;
    rl0_ver_cred_bind.claim_name <== rl0_cred_bind_name;
    rl0_ver_cred_bind.claim_value <== rl0_cred_bind_value;

    component rl1_ver_cred_bind = VerifyClaimMembershipString(rl_n_claims, 9);
    rl1_ver_cred_bind.hashed_claims <== rl1_hashed_claims;
    rl1_ver_cred_bind.claim_name <== rl1_cred_bind_name;
    rl1_ver_cred_bind.claim_value <== rl1_cred_bind_value;

    component rl2_ver_cred_bind = VerifyClaimMembershipString(rl_n_claims, 9);
    rl2_ver_cred_bind.hashed_claims <== rl2_hashed_claims;
    rl2_ver_cred_bind.claim_name <== rl2_cred_bind_name;
    rl2_ver_cred_bind.claim_value <== rl2_cred_bind_value;

    component diploma_enforce_binding = StringEquals(15);
    diploma_enforce_binding.a <== identity_cred_bind_value;
    diploma_enforce_binding.b <== diploma_cred_bind_value;
    1 === diploma_enforce_binding.out;

    component rl0_enforce_binding = StringEquals(15);
    rl0_enforce_binding.a <== identity_cred_bind_value;
    rl0_enforce_binding.b <== rl0_cred_bind_value;
    1 === rl0_enforce_binding.out;

    component rl1_enforce_binding = StringEquals(15);
    rl1_enforce_binding.a <== identity_cred_bind_value;
    rl1_enforce_binding.b <== rl1_cred_bind_value;
    1 === rl1_enforce_binding.out;

    component rl2_enforce_binding = StringEquals(15);
    rl2_enforce_binding.a <== identity_cred_bind_value;
    rl2_enforce_binding.b <== rl2_cred_bind_value;
    1 === rl2_enforce_binding.out;

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

    // Check degree is Computer Science MSc
    component diploma_ver_degree = VerifyClaimMembershipString(diploma_n_claims, 16);
    diploma_ver_degree.hashed_claims <== diploma_hashed_claims;
    diploma_ver_degree.claim_name <== diploma_degree_name;
    diploma_ver_degree.claim_value <== diploma_degree_value;

    component degree_check = StringEquals(15);
    degree_check.a <== degree_string;
    degree_check.b <== diploma_degree_value;
    signal degree_valid <== degree_check.out;

    // Check professions
    component rl0_ver_profession = VerifyClaimMembershipString(rl_n_claims, 16);
    rl0_ver_profession.hashed_claims <== rl0_hashed_claims;
    rl0_ver_profession.claim_name <== rl0_profession_name;
    rl0_ver_profession.claim_value <== rl0_profession_value;

    component rl1_ver_profession = VerifyClaimMembershipString(rl_n_claims, 16);
    rl1_ver_profession.hashed_claims <== rl1_hashed_claims;
    rl1_ver_profession.claim_name <== rl1_profession_name;
    rl1_ver_profession.claim_value <== rl1_profession_value;

    component rl2_ver_profession = VerifyClaimMembershipString(rl_n_claims, 16);
    rl2_ver_profession.hashed_claims <== rl2_hashed_claims;
    rl2_ver_profession.claim_name <== rl2_profession_name;
    rl2_ver_profession.claim_value <== rl2_profession_value;

    // > rl0
    component rl0_check_sec_eng = StringEquals(15);
    rl0_check_sec_eng.a <== sec_enc_string;
    rl0_check_sec_eng.b <== rl0_profession_value;
    
    component rl0_check_sec_analyst = StringEquals(15);
    rl0_check_sec_analyst.a <== sec_analyst_string;
    rl0_check_sec_analyst.b <== rl0_profession_value;

    signal rl0_profession_valid <== rl0_check_sec_eng.out + rl0_check_sec_analyst.out;

    // > rl1
    component rl1_check_sec_eng = StringEquals(15);
    rl1_check_sec_eng.a <== sec_enc_string;
    rl1_check_sec_eng.b <== rl1_profession_value;
    
    component rl1_check_sec_analyst = StringEquals(15);
    rl1_check_sec_analyst.a <== sec_analyst_string;
    rl1_check_sec_analyst.b <== rl1_profession_value;

    signal rl1_profession_valid <== rl1_check_sec_eng.out + rl1_check_sec_analyst.out;

    // > rl2
    component rl2_check_sec_eng = StringEquals(15);
    rl2_check_sec_eng.a <== sec_enc_string;
    rl2_check_sec_eng.b <== rl2_profession_value;
    
    component rl2_check_sec_analyst = StringEquals(15);
    rl2_check_sec_analyst.a <== sec_analyst_string;
    rl2_check_sec_analyst.b <== rl2_profession_value;

    signal rl2_profession_valid <== rl2_check_sec_eng.out + rl2_check_sec_analyst.out;

    component profession_check = MultiAND(3);
    profession_check.in[0] <== rl0_profession_valid;
    profession_check.in[1] <== rl1_profession_valid;
    profession_check.in[2] <== rl2_profession_valid;
    signal profession_valid <== profession_check.out;

    // Check years of experience
    component rl0_ver_start_date = VerifyClaimMembership(rl_n_claims, 17);
    rl0_ver_start_date.hashed_claims <== rl0_hashed_claims;
    rl0_ver_start_date.claim_name <== rl0_start_date_name;
    rl0_ver_start_date.claim_value <== rl0_start_date_value;

    component rl0_ver_end_date = VerifyClaimMembership(rl_n_claims, 18);
    rl0_ver_end_date.hashed_claims <== rl0_hashed_claims;
    rl0_ver_end_date.claim_name <== rl0_end_date_name;
    rl0_ver_end_date.claim_value <== rl0_end_date_value;

    component rl1_ver_start_date = VerifyClaimMembership(rl_n_claims, 17);
    rl1_ver_start_date.hashed_claims <== rl1_hashed_claims;
    rl1_ver_start_date.claim_name <== rl1_start_date_name;
    rl1_ver_start_date.claim_value <== rl1_start_date_value;

    component rl1_ver_end_date = VerifyClaimMembership(rl_n_claims, 18);
    rl1_ver_end_date.hashed_claims <== rl1_hashed_claims;
    rl1_ver_end_date.claim_name <== rl1_end_date_name;
    rl1_ver_end_date.claim_value <== rl1_end_date_value;

    component rl2_ver_start_date = VerifyClaimMembership(rl_n_claims, 17);
    rl2_ver_start_date.hashed_claims <== rl2_hashed_claims;
    rl2_ver_start_date.claim_name <== rl2_start_date_name;
    rl2_ver_start_date.claim_value <== rl2_start_date_value;
    
    component rl2_ver_end_date = VerifyClaimMembership(rl_n_claims, 18);
    rl2_ver_end_date.hashed_claims <== rl2_hashed_claims;
    rl2_ver_end_date.claim_name <== rl2_end_date_name;
    rl2_ver_end_date.claim_value <== rl2_end_date_value;

    signal rl0_experience_years <== rl0_end_date_value - rl0_start_date_value;
    signal rl1_experience_years <== rl1_end_date_value - rl1_start_date_value;
    signal rl2_experience_years <== rl2_end_date_value - rl2_start_date_value;

    signal tot_experience_years <== rl0_experience_years + rl1_experience_years + rl2_experience_years;

    component check_experience_years = LessThan(128);
    check_experience_years.in[0] <== five_years;
    check_experience_years.in[1] <== tot_experience_years;
    signal more_5y_experience <== age_check.out;

    component m_and = MultiAND(6);
    m_and.in[0] <== all_creds_valid;
    m_and.in[1] <== age_over_18;
    m_and.in[2] <== university_valid;
    m_and.in[3] <== degree_valid;
    m_and.in[4] <== profession_valid;
    m_and.in[5] <== more_5y_experience;

    out <== m_and.out;

}

component main {public [iss_pk_x, iss_pk_y, over_18, identity_vct_comp, diploma_vct_comp, rl_vct_comp, ethz_string, epfl_string, degree_string, sec_enc_string, sec_analyst_string, five_years, now_timestamp, identity_vct_name, identity_exp_name, identity_cred_bind_name, identity_status_list, identity_status_list_uri_name, identity_status_list_uri_value, identity_status_list_idx_name, identity_date_offset_name, identity_date_offset_value, identity_birthdate_name, diploma_vct_name, diploma_exp_name, diploma_cred_bind_name, diploma_date_offset_name, diploma_date_offset_value, diploma_university_name, diploma_degree_name, rl0_vct_name, rl0_exp_name, rl0_cred_bind_name, rl0_date_offset_name, rl0_date_offset_value, rl0_profession_name, rl0_start_date_name, rl0_end_date_name, rl1_vct_name, rl1_exp_name, rl1_cred_bind_name, rl1_date_offset_name, rl1_date_offset_value, rl1_profession_name, rl1_start_date_name, rl1_end_date_name, rl2_vct_name, rl2_exp_name, rl2_cred_bind_name, rl2_date_offset_name, rl2_date_offset_value, rl2_profession_name, rl2_start_date_name, rl2_end_date_name]} = Proof(22, 18, 19, 1024);