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

package org.osiam.resource_server.resources.provisioning.update;

import java.util.List;
import java.util.Set;

import org.osiam.resource_server.resources.converter.AddressConverter;
import org.osiam.resources.scim.Address;
import org.osiam.resource_server.storage.entities.AddressEntity;
import org.osiam.resource_server.storage.entities.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

/**
 * The AddressUpdater provides the functionality to update the {@link AddressEntity} of a UserEntity
 */
@Service
class AddressUpdater {

    @Autowired
    private AddressConverter addressConverter;

    /**
     * updates (adds new, delete, updates) the addresses of the given {@link UserEntity} based on the given List of
     * {@link Address}
     * 
     * @param addresss
     *            list of {@link Address} to be deleted, updated or added
     * @param userEntity
     *            user who needs to be updated
     * @param attributes
     *            all {@link AddressEntity}'s will be deleted if this Set contains 'address'
     */
    void update(List<Address> addresss, UserEntity userEntity, Set<String> attributes) {

        if (attributes.contains("addresses")) {
            userEntity.removeAllAddresses();
        }

        if (addresss != null) {
            for (Address scimAddress : addresss) {
                AddressEntity addressEntity = addressConverter.fromScim(scimAddress);
                userEntity.removeAddress(addressEntity); // we always have to remove the address in case
                                                         // the primary attribute has changed
                if (Strings.isNullOrEmpty(scimAddress.getOperation())
                        || !scimAddress.getOperation().equalsIgnoreCase("delete")) {

                    ensureOnlyOnePrimaryAddressExists(addressEntity, userEntity.getAddresses());
                    userEntity.addAddress(addressEntity);
                }
            }
        }
    }

    /**
     * if the given newAddress is set to primary the primary attribute of all existing address's in the
     * {@link UserEntity} will be removed
     * 
     * @param newAddress
     *            to be checked if it is primary
     * @param addresss
     *            all existing address's of the {@link UserEntity}
     */
    private void ensureOnlyOnePrimaryAddressExists(AddressEntity newAddress, Set<AddressEntity> addresss) {
        if (newAddress.isPrimary()) {
            for (AddressEntity exisitngAddressEntity : addresss) {
                if (exisitngAddressEntity.isPrimary()) {
                    exisitngAddressEntity.setPrimary(false);
                }
            }
        }
    }

}
