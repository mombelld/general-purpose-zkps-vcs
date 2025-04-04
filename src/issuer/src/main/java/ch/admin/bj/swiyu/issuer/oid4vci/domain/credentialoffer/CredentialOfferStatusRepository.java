package ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialOfferStatusRepository extends JpaRepository<CredentialOfferStatus, CredentialOfferStatusKey> {
}
