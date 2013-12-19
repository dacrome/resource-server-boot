/*
 * Copyright (C) 2013 tarent AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.osiam.resources.provisioning.update;

import java.util.List;
import java.util.Set;

import javax.inject.Inject;

import org.osiam.resources.converter.EntitlementConverter;
import org.osiam.resources.scim.MultiValuedAttribute;
import org.osiam.storage.entities.EntitlementsEntity;
import org.osiam.storage.entities.UserEntity;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

/**
 * The EntitlementsUpdater provides the functionality to update the {@link EntitlementsEntity} of a UserEntity
 */
@Service
class EntitlementsUpdater {

    @Inject
    private EntitlementConverter entitlementConverter;

    /**
     * updates (adds new, delete, updates) the {@link EntitlementsEntity}'s of the given {@link UserEntity} based on the
     * given List of Entitlement's
     *
     * @param entitlements
     *            list of Entitlement's to be deleted, updated or added
     * @param userEntity
     *            user who needs to be updated
     * @param attributes
     *            all {@link EntitlementsEntity}'s will be deleted if this Set contains 'entitlements'
     */
    void update(List<MultiValuedAttribute> entitlements, UserEntity userEntity, Set<String> attributes) {

        if (attributes.contains("entitlements")) {
            userEntity.removeAllEntitlements();
        }

        if (entitlements != null) {
            for (MultiValuedAttribute scimEntitlements : entitlements) {
                EntitlementsEntity entitlementsEntity = entitlementConverter.fromScim(scimEntitlements);
                userEntity.removeEntitlement(entitlementsEntity); // we always have to remove the entitlement's in case
                // the active flag has changed
                if (Strings.isNullOrEmpty(scimEntitlements.getOperation())
                        || !scimEntitlements.getOperation().equalsIgnoreCase("delete")) {

                    // TODO primary is not implemented yet. If it is see EmailUpdater how to implement it here
                    userEntity.addEntitlement(entitlementsEntity);
                }
            }
        }
    }

}
