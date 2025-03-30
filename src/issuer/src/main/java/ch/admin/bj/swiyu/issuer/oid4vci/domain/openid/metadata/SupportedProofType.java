package ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class SupportedProofType {
    @JsonProperty("proof_signing_alg_values_supported")
    List<String> supportedSigningAlgorithms;

}
