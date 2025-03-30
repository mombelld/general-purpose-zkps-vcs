package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.oid4vci.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.CredentialException;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.IssuerMetadataTechnical;
import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Map;
import java.util.HashMap;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Paths;

import static ch.admin.bj.swiyu.issuer.oid4vci.common.exception.CredentialRequestError.INVALID_PROOF;
import static ch.admin.bj.swiyu.issuer.oid4vci.common.utils.TimeUtils.getUnixTimeStamp;
import static ch.admin.bj.swiyu.issuer.oid4vci.common.utils.TimeUtils.instantToUnixTimestamp;
import static java.util.Objects.nonNull;

// Zk Credentials
import ch.admin.bj.swiyu.issuer.oid4vci.zk.CredentialZK;

@Slf4j
public class SdJwtCredential extends CredentialBuilder {

    private final SdjwtProperties sdjwtProperties;
    private final String zkSigningKey;


    public SdJwtCredential(ApplicationProperties applicationProperties, IssuerMetadataTechnical issuerMetadata, DataIntegrityService dataIntegrityService, SdjwtProperties sdjwtProperties, JWSSigner signer) {
        super(applicationProperties, issuerMetadata, dataIntegrityService, signer);
        this.zkSigningKey = sdjwtProperties.getZkSigningKey();
        this.sdjwtProperties = sdjwtProperties;
    }

    @Override
    public String getCredential() {

        SDObjectBuilder builder = new SDObjectBuilder();
        var metadataId = getMetadataCredentialsSupportedIds().getFirst();

        long iat = getUnixTimeStamp();

        HashMap<String, Object> credOfferData = ( HashMap<String, Object>) getCredentialOffer().getOfferData();

        // Zk vc
        CredentialZK credZk = CredentialZK.builder()
                .iss(getApplicationProperties().getIssuerId())
                .vct(getIssuerMetadata().getCredentialConfigurationById(metadataId).getVct())
                .iat(Instant.ofEpochSecond(iat))
                .offerData(getOfferData())
                .nbf(getCredentialOffer().getCredentialValidFrom())
                .exp(getCredentialOffer().getCredentialValidUntil())
                .statusIndex((Long) credOfferData.get("status_list_idx"))
                .statusList((String) credOfferData.get("status_list_uri"))
                .hardwarePkx(new BigInteger((String) credOfferData.get("cnf_jwk_x"), 16))
                .hardwarePky(new BigInteger((String) credOfferData.get("cnf_jwk_y"), 16))
                .credentialBind((String) credOfferData.get("cred_bind"))
                .signingKey(zkSigningKey)
                .build();

        String[] signedRoot = credZk.getSignedRoot();

        // Mandatory claims or claims which always need to be disclosed according to SD-JWT VC specification
        builder.putClaim("iss", getApplicationProperties().getIssuerId());
        // Get first entry because we expect the list to only contain one item
        builder.putClaim("vct", getIssuerMetadata().getCredentialConfigurationById(metadataId).getVct());
        builder.putClaim("iat", iat);

        // optional field -> only added when set
        if (nonNull(getCredentialOffer().getCredentialValidFrom())) {
            builder.putClaim("nbf", instantToUnixTimestamp(getCredentialOffer().getCredentialValidFrom()));
        }

        // optional field -> only added when set
        if (nonNull(getCredentialOffer().getCredentialValidUntil())) {
            builder.putClaim("exp", instantToUnixTimestamp(getCredentialOffer().getCredentialValidUntil()));
        }

        getHolderBinding().ifPresent(didJwk -> {
            try {
                builder.putClaim("cnf", didJwk.getJWK().toJSONObject());
            } catch (ParseException e) {
                throw new Oid4vcException(
                        e,
                        INVALID_PROOF,
                        String.format("Failed expand holder binding %s to cnf", didJwk.getDidJwk())
                );
            }
        });

        // Add zk
        builder.putClaim("zk_root", signedRoot[0]);
        builder.putClaim("zk_r", signedRoot[1]);
        builder.putClaim("zk_s", signedRoot[2]);
        builder.putClaim("status_list_idx", credZk.getStatusIndex());
        builder.putClaim("status_list_uri", credZk.getStatusList());
        builder.putClaim("cnf_jwk_x", credZk.getHardwarePkx().toString());
        builder.putClaim("cnf_jwk_y", credZk.getHardwarePky().toString());
        builder.putClaim("cred_bind", credZk.getCredentialBind());
        builder.putClaim("date_offset", CredentialZK.getDateOffset());
        

        //Add all status entries (if any)
        for (Map.Entry<String, Object> statusEntry : getStatusReferences().entrySet()) {
            builder.putClaim(statusEntry.getKey(), statusEntry.getValue());
        }
        // https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.2.2.2
        // Registered JWT claims MUST be included not as always disclosed
        // sub & iat may explicitly be selectively disclosed
        var protectedClaims = List.of("iss", "nbf", "exp", "iat", "cnf", "vct", "status");


        // Optional claims as disclosures
        // Code below follows example from https://github.com/authlete/sd-jwt?tab=readme-ov-file#credential-jwt
        List<Disclosure> disclosures = new ArrayList<>();
        for (var entry : getOfferData().entrySet()) {
            if (protectedClaims.contains(entry.getKey())) {
                // We only log the issue and do not add the claim.
                log.warn("Upstream application tried to override protected claim {} in credential offer {}. Original value has been retained",
                        entry.getKey(), getCredentialOffer().getId());
                continue;
            }
            // TODO: EID-1782; Handle mandatory subject fields using issuer metadata
            Disclosure dis = new Disclosure(entry.getKey(), entry.getValue());
            disclosures.add(dis);
            builder.putSDClaim(dis);
        }

        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("vc+sd-jwt"))
                    .keyID(sdjwtProperties.getVerificationMethod())
                    .customParam("ver", sdjwtProperties.getVersion())
                    .build();
            JWTClaimsSet claimsSet = JWTClaimsSet.parse(builder.build(true));
            SignedJWT jwt = new SignedJWT(header, claimsSet);

            jwt.sign(this.getSigner());

            String vcOut = new SDJWT(jwt.serialize(), disclosures).toString();

            // For simplicity of implementation print credential to file
            try {
                String currentPath = System.getProperty("user.dir");
                String offerId = getCredentialOffer().getId().toString();
                String credOutPath = Paths.get(currentPath.toString(), "..", "..", "credentials", offerId + "-zk.sdjwt").toString();
                FileWriter writer = new FileWriter(credOutPath);
                writer.write(vcOut);
                writer.close();
                
            } catch (IOException e) {
                log.error("Failed to write credential to file", e);
                e.printStackTrace();
            }

            return vcOut;
        } catch (ParseException | JOSEException e) {
            throw new CredentialException(e);
        }
    }
}
