/*
 * SPDX-FileCopyrightText: 2024 Swiss Confederation
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer;

import java.util.Map;

public interface VerifiableCredentialStatusReference {
    /**
     * Create a hashmap as to be used in the claims of a verifiable credential
     */
    Map<String, Object> createVCRepresentation();
}
