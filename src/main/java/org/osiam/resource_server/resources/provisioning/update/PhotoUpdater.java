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

import org.osiam.resource_server.resources.converter.PhotoConverter;
import org.osiam.resource_server.storage.entities.PhotoEntity;
import org.osiam.resource_server.storage.entities.UserEntity;
import org.osiam.resources.scim.Photo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

/**
 * The PhotoUpdater provides the functionality to update the {@link PhotoEntity} of a UserEntity
 */
@Service
class PhotoUpdater {

    @Autowired
    private PhotoConverter photoConverter;

    /**
     * updates (adds new, delete, updates) the {@link PhotoEntity}'s of the given {@link UserEntity} based on the given
     * List of Photo's
     * 
     * @param photos
     *            list of Photo's to be deleted, updated or added
     * @param userEntity
     *            user who needs to be updated
     * @param attributes
     *            all {@link PhotoEntity}'s will be deleted if this Set contains 'photos'
     */
    void update(List<Photo> photos, UserEntity userEntity, Set<String> attributes) {

        if (attributes.contains("photos")) {
            userEntity.removeAllPhotos();
        }

        if (photos != null) {
            for (Photo scimPhoto : photos) {
                PhotoEntity photoEntity = photoConverter.fromScim(scimPhoto);
                userEntity.removePhoto(photoEntity); // we always have to remove the photo in case
                                                     // the primary attribute has changed
                if (Strings.isNullOrEmpty(scimPhoto.getOperation())
                        || !scimPhoto.getOperation().equalsIgnoreCase("delete")) {

                    ensureOnlyOnePrimaryPhotoExists(photoEntity, userEntity.getPhotos());
                    userEntity.addPhoto(photoEntity);
                }
            }
        }
    }

    /**
     * if the given newPhoto is set to primary the primary attribute of all existing photo's in the {@link UserEntity}
     * will be removed
     * 
     * @param newPhoto
     *            to be checked if it is primary
     * @param photos
     *            all existing photo's of the {@link UserEntity}
     */
    private void ensureOnlyOnePrimaryPhotoExists(PhotoEntity newPhoto, Set<PhotoEntity> photos) {
        if (newPhoto.isPrimary()) {
            for (PhotoEntity exisitngPhotoEntity : photos) {
                if (exisitngPhotoEntity.isPrimary()) {
                    exisitngPhotoEntity.setPrimary(false);
                }
            }
        }
    }
}
