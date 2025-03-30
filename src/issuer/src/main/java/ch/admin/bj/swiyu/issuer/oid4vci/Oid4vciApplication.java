package ch.admin.bj.swiyu.issuer.oid4vci;

import lombok.extern.slf4j.Slf4j;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.env.Environment;

import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialStatus;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.CredentialRequest;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.IssuerMetadataTechnical;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.oid4vci.service.CredentialFormatFactory;
import ch.admin.bj.swiyu.issuer.oid4vci.service.DataIntegrityService;
import ch.admin.bj.swiyu.issuer.oid4vci.infrastructure.web.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.SignerConfig;
import com.nimbusds.jose.JWSSigner;
import org.springframework.core.io.FileUrlResource;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.util.UUID;
import java.util.HashMap;
import java.nio.file.Paths;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.time.Instant;
import java.util.List;



@SpringBootApplication
@EnableConfigurationProperties
@Slf4j
public class Oid4vciApplication {

    private final static String currentPath = System.getProperty("user.dir");
    private final static String credOfferPath = Paths.get(currentPath.toString(), "..", "..", "credential_offers", "cred_offer.json").toString();

    public static void main(String[] args) throws Exception {
        Environment env = SpringApplication.run(Oid4vciApplication.class, args).getEnvironment();
        // String appName = env.getProperty("spring.application.name");
        // String serverPort = env.getProperty("server.port");
        // log.info(
        //     """
                
        //     ----------------------------------------------------------------------------
        //     \t'{}' is running!\s
        //     \tProfile(s): \t\t\t\t{}
        //     \tSwaggerUI:   \t\t\t\thttp://localhost:{}/swagger-ui.html
        //     ----------------------------------------------------------------------------""",
        //     appName,
        //     env.getActiveProfiles(),
        //     serverPort
        //     );
        CredentialOffer credentialOffer = getCredentialOffer(CredentialStatus.OFFERED);

        CredentialRequest credentialRequest = new CredentialRequest();
        credentialRequest.setCredentialResponseEncryption(null);

        
        ApplicationProperties applicationProperties = new ApplicationProperties();

        OpenIdIssuerConfiguration openIdIssuerConfiguration = new OpenIdIssuerConfiguration(applicationProperties);
        applicationProperties.setIssuerId(env.getProperty("application.issuer-id"));
        openIdIssuerConfiguration.setIssuerMetadataResource(new FileUrlResource("src/main/resources/issuer_metadata.json"));


        IssuerMetadataTechnical issuerMetadata = openIdIssuerConfiguration.getIssuerMetadataTechnical();
        DataIntegrityService dataIntegrityService = new DataIntegrityService(applicationProperties);

        SdjwtProperties sdjwtProperties = new SdjwtProperties();
        sdjwtProperties.setKeyManagementMethod("key");
        sdjwtProperties.setPrivateKey(env.getProperty("application.key.sdjwt.private-key"));
        sdjwtProperties.setZkSigningKey(env.getProperty("application.key.zk.private-key"));

        SignerConfig signerConfig = new SignerConfig(sdjwtProperties);
        JWSSigner signer;
        signer = signerConfig.defaultSigner();

        CredentialFormatFactory vcFormatFactory = new CredentialFormatFactory(
                applicationProperties,
                issuerMetadata,
                dataIntegrityService,
                sdjwtProperties,
                signer);

        var vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .build();


        System.exit(0);

    }

    public static CredentialOffer getCredentialOffer(CredentialStatus status) {
        JSONParser parser = new JSONParser();
        
        try{
            JSONObject credOffer = (JSONObject) parser.parse(new FileReader(credOfferPath));
            UUID offerId = UUID.fromString((String) credOffer.get("offer_id"));
            String vct = (String) credOffer.get("vct");
            String nbf = (String) credOffer.get("nbf");
            String exp = (String) credOffer.get("exp");

            JSONObject tmpOfferData = (JSONObject) credOffer.get("offer_data");
            HashMap<String, Object> offerData = new HashMap<>();
            offerData.put("data", tmpOfferData.get("data").toString());
            offerData.put("cnf_jwk_x", (String) ((JSONObject) tmpOfferData.get("cnf")).get("x"));
            offerData.put("cnf_jwk_y", (String) ((JSONObject) tmpOfferData.get("cnf")).get("y"));
            offerData.put("cred_bind", (String) tmpOfferData.get("cred_bind"));
            offerData.put("status_list_idx", (Long) ((JSONObject) tmpOfferData.get("status_list")).get("idx"));
            offerData.put("status_list_uri", (String) ((JSONObject) tmpOfferData.get("status_list")).get("uri"));

            return new CredentialOffer(
                    offerId,
                    status,
                    List.of(vct),
                    offerData,
                    UUID.randomUUID(),
                    UUID.randomUUID(),
                    (int) Instant.now().plusSeconds(120).getEpochSecond(),
                    Instant.parse(nbf),
                    Instant.parse(exp),
                    null
            );
        } catch (FileNotFoundException e) {
            log.error("Could not find credential offer file.", e);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            log.error("Invalid credential offer format.", e);
        }

        return null;

    }

    
}
