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

import org.osiam.resource_server.resources.converter.ImConverter;
import org.osiam.resource_server.storage.entities.ImEntity;
import org.osiam.resource_server.storage.entities.UserEntity;
import org.osiam.resources.scim.Im;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

/**
 * The ImUpdater provides the functionality to update the {@link ImEntity} of a UserEntity
 */
@Service
class ImUpdater {

    @Autowired
    private ImConverter imConverter;

    /**
     * updates (adds new, delete, updates) the {@link ImEntity}'s of the given {@link UserEntity} based on the given
     * List of Im's
     * 
     * @param ims
     *            list of Im's to be deleted, updated or added
     * @param userEntity
     *            user who needs to be updated
     * @param attributes
     *            all {@link ImEntity}'s will be deleted if this Set contains 'ims'
     */
    void update(List<Im> ims, UserEntity userEntity, Set<String> attributes) {

        if (attributes.contains("ims")) {
            userEntity.removeAllIms();
        }

        if (ims != null) {
            for (Im scimIm : ims) {
                ImEntity imEntity = imConverter.fromScim(scimIm);
                userEntity.removeIm(imEntity); // we always have to remove the im in case
                                               // the primary attribute has changed
                if (Strings.isNullOrEmpty(scimIm.getOperation())
                        || !scimIm.getOperation().equalsIgnoreCase("delete")) {

                    ensureOnlyOnePrimaryImExists(imEntity, userEntity.getIms());
                    userEntity.addIm(imEntity);
                }
            }
        }
    }

    /**
     * if the given newIm is set to primary the primary attribute of all existing im's in the {@link UserEntity} will be
     * removed
     * 
     * @param newIm
     *            to be checked if it is primary
     * @param ims
     *            all existing im's of the {@link UserEntity}
     */
    private void ensureOnlyOnePrimaryImExists(ImEntity newIm, Set<ImEntity> ims) {
        if (newIm.isPrimary()) {
            for (ImEntity exisitngImEntity : ims) {
                if (exisitngImEntity.isPrimary()) {
                    exisitngImEntity.setPrimary(false);
                }
            }
        }
    }
}
