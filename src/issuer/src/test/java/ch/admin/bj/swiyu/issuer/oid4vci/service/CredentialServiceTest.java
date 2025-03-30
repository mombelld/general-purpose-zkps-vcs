package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.oid4vci.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialOfferStatus;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialStatus;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.CredentialRequest;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.IssuerMetadataTechnical;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mockConstructionWithAnswer;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class CredentialServiceTest {

    @Mock
    private CredentialOfferRepository credentialOfferRepository;
    @Mock
    private IssuerMetadataTechnical issuerMetadata;
    @Mock
    private CredentialFormatFactory vcFormatFactory;
    @Mock
    private ApplicationProperties applicationProperties;

    @Test
    public void givenExpiredOffer_whenCredentialIsCreated_throws() {
        // GIVEN
        var service = new CredentialService(credentialOfferRepository, issuerMetadata, vcFormatFactory, applicationProperties, null);
        var uuid = UUID.randomUUID();
        var offerData = new HashMap<String, Object>() {{
            put("data", "data");
            put("otherStuff", "data");
        }};
        var offer = new CredentialOffer(
                UUID.randomUUID(),
                CredentialStatus.OFFERED,
                Collections.emptyList(),
                offerData,
                uuid,
                UUID.randomUUID(),
                120,
                Instant.now(),
                Instant.now(),
                null
        );
        when(credentialOfferRepository.findByAccessToken(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var ex = assertThrows(OAuthException.class, () -> service.createCredential(CredentialRequest.builder().build(), uuid.toString()));

        // THEN Status is changed and offer data is cleared
        assertEquals(CredentialStatus.EXPIRED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());
        assertEquals( "INVALID_REQUEST", ex.getError().toString());
        assertEquals( "Invalid accessToken", ex.getMessage());
    }

    @Test
    public void givenExpiredOffer_whenTokenIsCreated_throws() {
        // GIVEN
        var service = new CredentialService(credentialOfferRepository, issuerMetadata, vcFormatFactory, applicationProperties, null);
        var uuid = UUID.randomUUID();
        var offerData = new HashMap<String, Object>() {{
            put("data", "data");
            put("otherStuff", "data");
        }};
        var offer = new CredentialOffer(
                uuid,
                CredentialStatus.OFFERED,
                Collections.emptyList(),
                offerData,
                UUID.randomUUID(),
                UUID.randomUUID(),
                120,
                Instant.now(),
                Instant.now(),
                null
        );
        when(credentialOfferRepository.findById(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var ex = assertThrows(OAuthException.class, () -> service.issueOAuthToken(uuid.toString()));

        // THEN Status is changed and offer data is cleared
        assertEquals(CredentialStatus.EXPIRED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());
        assertEquals( "INVALID_GRANT", ex.getError().toString());
        assertEquals( "Invalid preAuthCode", ex.getMessage());
    }
}
