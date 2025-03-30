package ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.Oid4vcException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

public class ProofJwt extends Proof {

    private final String jwt;
    private String holderKeyJson;

    public ProofJwt(ProofType proofType, String jwt) {
        super(proofType);
        this.jwt = jwt;
    }

    private static Oid4vcException proofException(String errorDescription) {
        return new Oid4vcException(CredentialRequestError.INVALID_PROOF, errorDescription);
    }

    @Override
    public boolean isValidHolderBinding(List<String> supportedSigningAlgorithms, String nonce) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(this.jwt);
            JWSHeader header = signedJWT.getHeader();
            if (!supportedSigningAlgorithms.contains(header.getAlgorithm().getName())) {
                throw proofException("Proof Signing Algorithm is not supported");
            }
            if (!header.getType().toString().equals(ProofType.JWT.getClaimTyp())) {
                throw proofException(String.format("Proof Type is not supported. Must be 'openid4vci-proof+jwt' but was %s", header.getType()));
            }

            ECKey holderKey = getNormalizedECKey(header);
            JWSVerifier verifier = new ECDSAVerifier(holderKey);

            if (!signedJWT.verify(verifier)) {
                throw proofException("Proof JWT is not valid!");
            }
            this.holderKeyJson = holderKey.toJSONString();

        } catch (ParseException e) {
            throw proofException("Provided Proof JWT is not parseable; " + e.getMessage());
        } catch (JOSEException e) {
            throw proofException("Key is not usable; " + e.getMessage());
        }

        return true;
    }

    @Override
    public String getBinding() {
        return this.holderKeyJson;
    }

    /**
     * Gets the ECKey from either kid with did or the cnf entry
     *
     * @return the Holder's ECKey
     */
    private ECKey getNormalizedECKey(JWSHeader header) {
        var kid = header.getKeyID();
        if (kid != null && !kid.isEmpty()) {
            try {
                return DidJwk.createFromDidJwk(kid).getJWK().toECKey();
            } catch (ParseException e) {
                throw proofException(String.format("kid property %s could not be parsed to a JWK", kid));
            }
        }
        return Optional.ofNullable(header.getJWK()).orElseThrow(() ->
                proofException("Missing jwk entry in header.")
        ).toECKey();
    }
}
