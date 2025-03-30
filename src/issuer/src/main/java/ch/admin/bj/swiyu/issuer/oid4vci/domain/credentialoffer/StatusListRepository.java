package ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface StatusListRepository extends JpaRepository<StatusList, UUID> {
}
