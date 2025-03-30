package ch.admin.bj.swiyu.issuer.oid4vci.infrastructure.web.config;

import io.swagger.v3.oas.models.OpenAPI;
import lombok.RequiredArgsConstructor;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class OpenApiConfig {
    private final BuildProperties buildProperties;
    @Bean
    public OpenAPI openApi() {
        return new OpenAPI().info(new io.swagger.v3.oas.models.info.Info()
                .title("Issuer OID4VCI service")
                .description("Generic Issuer OID4VCI service")
                .version(buildProperties.getVersion())
                .contact(new io.swagger.v3.oas.models.info.Contact()
                        .name("e-ID - Team Tergum")
                        .email("eid@bit.admin.ch")
                )
        );

    }

    @Bean
    GroupedOpenApi api() {
        return GroupedOpenApi.builder()
                .group("API")
                .pathsToMatch("/**")
                .build();
    }

}
