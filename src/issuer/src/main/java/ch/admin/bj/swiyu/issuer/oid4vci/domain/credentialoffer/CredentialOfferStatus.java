/*
 * SPDX-FileCopyrightText: 2024 Swiss Confederation
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "credential_offer_status")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@AllArgsConstructor // test data
public class CredentialOfferStatus {

    @EmbeddedId
    private CredentialOfferStatusKey id;

    @ManyToOne
    @MapsId("offerId")
    @JoinColumn(name = "credential_offer_id", referencedColumnName = "id")
    private CredentialOffer offer;

    @ManyToOne
    @MapsId("statusListId")
    @JoinColumn(name = "status_list_id", referencedColumnName = "id")
    private StatusList statusList;

    @Column
    private Integer index;

}
