pragma circom 2.1.2;

include "../../circuits/cred_ver.circom";
include "../../circuits/status_list_check.circom";
include "../../circuits/poseidon/poseidon.circom";
include "../../circuits/util/ver_claim_membership.circom";
include "../../circomlib/circuits/comparators.circom";
include "../../circomlib/circuits/gates.circom";


/**
 * Example of how one can exploit a proof, in this case we are dumping the whole content
 * of the credential
 */
template Proof(n_claims, sl_length) {
    // ---------------- Public inputs ----------------
    signal input now_timestamp;
    signal input iss_name;
    signal input iss_value[15];
    signal input vct_name;
    signal input vct_value[15];
    signal input iat_name;
    signal input iat_value;
    signal input nbf_name;
    signal input nbf_value;
    signal input exp_name;
    signal input exp_value;
    signal input status_list[sl_length];
    signal input status_list_idx_name;
    signal input status_list_idx_value;
    signal input status_list_uri_name;
    signal input status_list_uri_value[15];
    signal input cnf_jwk_x_name;
    signal input cnf_jwk_x_value;
    signal input cnf_jwk_y_name;
    signal input cnf_jwk_y_value;
    signal input cred_bind_name;
    signal input cred_bind_value[15];
    signal input date_offset_name;
    signal input date_offset_value;
    signal input first_name_name;
    signal input first_name_value[15];
    signal input last_name_name;
    signal input last_name_value[15];
    signal input email_name;
    signal input email_value[15];
    signal input phone_number_name;
    signal input phone_number_value[15];
    signal input nationality_name;
    signal input nationality_value[15];
    signal input address_name;
    signal input address_value[15];
    signal input locality_name;
    signal input locality_value[15];
    signal input canton_name;
    signal input canton_value[15];
    signal input postcode_name;
    signal input postcode_value;
    signal input country_name;
    signal input country_value[15];
    signal input birthdate_name;
    signal input birthdate_value;
    signal input hashed_claims[n_claims];
    signal input zk_r;
    signal input zk_s;
    signal input hb_ux;
    signal input hb_uy;
    signal input hb_powers[32][256][2][6];
    signal input hb_R_x;
    signal input hb_R_y;
    signal input hb_r;
    signal input hb_s;

    signal output out[25];

    out[0] <== iss_value[0];
    out[1] <== vct_value[0];
    out[2] <== iat_value;
    out[3] <== nbf_value;
    out[4] <== exp_value;
    out[5] <== status_list_idx_value;
    out[6] <== status_list_uri_value[0];
    out[7] <== cnf_jwk_x_value;
    out[8] <== cnf_jwk_y_value;
    out[9] <== cred_bind_value[0];
    out[10] <== date_offset_value;
    out[11] <== first_name_value[0];
    out[12] <== last_name_value[0];
    out[13] <== email_value[0];
    out[14] <== phone_number_value[0];
    out[15] <== nationality_value[0];
    out[16] <== address_value[0];
    out[17] <== locality_value[0];
    out[18] <== canton_value[0];
    out[19] <== postcode_value;
    out[20] <== country_value[0];
    out[21] <== birthdate_value;
    out[22] <== zk_r;
    out[23] <== zk_s;
    out[24] <== exp_value * nbf_value;

}

component main {public [exp_name]} = Proof(22, 1024);