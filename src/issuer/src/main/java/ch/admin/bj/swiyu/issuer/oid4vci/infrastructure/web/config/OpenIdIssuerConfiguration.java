package ch.admin.bj.swiyu.issuer.oid4vci.infrastructure.web.config;

import ch.admin.bj.swiyu.issuer.oid4vci.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.api.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.IssuerMetadataTechnical;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.util.PropertyPlaceholderHelper;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.lang.Thread;

@Configuration
@Data
public class OpenIdIssuerConfiguration {

    private final ApplicationProperties applicationProperties;

    @Value("${application.openid-file}")
    private Resource openIdResource;

    @Value("${application.metadata-file}")
    private Resource issuerMetadataResource;

    @Cacheable("OpenIdConfiguration")
    public OpenIdConfigurationDto getOpenIdConfiguration() throws IOException {
        return resourceToMappedData(openIdResource, OpenIdConfigurationDto.class);
    }

    /**
     * @return the full Issuer Metadata in a recursive Map
     * @throws IOException if the Issuer Metadata json file is not found
     */
    @Cacheable("IssuerMetadata")
    public Map<String, Object> getIssuerMetadata() throws IOException {
        return resourceToMappedData(issuerMetadataResource, HashMap.class);
    }

    /**
     * @return Issuer Metadata for using in creation of a vc
     * @throws IOException if the required json resource is not found
     */
    @Bean
    public IssuerMetadataTechnical getIssuerMetadataTechnical() throws IOException {
        return resourceToMappedData(issuerMetadataResource, IssuerMetadataTechnical.class);
        // return null;
    }

    private String replaceExternalUri(String template) {
        Properties prop = new Properties();
        for (Map.Entry<String, String> replacementEntrySet : applicationProperties.getTemplateReplacement().entrySet()) {
            prop.setProperty(replacementEntrySet.getKey(), replacementEntrySet.getValue());
        }
        PropertyPlaceholderHelper helper = new PropertyPlaceholderHelper("${", "}");
        return helper.replacePlaceholders(template, prop);
    }

    private <T> T resourceToMappedData(Resource res, Class<T> clazz) throws IOException {
        var json = res.getContentAsString(Charset.defaultCharset());
        // json = replaceExternalUri(json);
        return new ObjectMapper().readValue(json, clazz);
    }

}
