pragma circom 2.1.2;
include "../../cred_ver.circom";
template Ver() {
signal input Qx;
signal input Qy;
signal input hashed_claims[8];
signal input r;
signal input s;
component vc = VerifyCredential(8);
vc.Qx <== Qx;
vc.Qy <== Qy;
vc.hashed_claims <== hashed_claims;
vc.r <== r;
vc.s <== s;
vc.valid === 1;
}
component main = Ver();