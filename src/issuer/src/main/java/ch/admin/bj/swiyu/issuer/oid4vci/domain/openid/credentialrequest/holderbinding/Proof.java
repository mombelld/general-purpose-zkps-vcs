package ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.holderbinding;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@AllArgsConstructor
@Getter
public abstract class Proof {
    public final ProofType proofType;

    public abstract boolean isValidHolderBinding(List<String> supportedSigningAlgorithms, String nonce);

    public abstract String getBinding();
}
