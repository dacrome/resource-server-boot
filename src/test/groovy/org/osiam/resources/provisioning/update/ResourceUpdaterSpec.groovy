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

package org.osiam.resource_server.resources.provisioning.update

import org.osiam.resource_server.resources.exceptions.ResourceExistsException
import org.osiam.resources.scim.Group
import org.osiam.resources.scim.Meta
import org.osiam.resource_server.storage.dao.ResourceDao
import org.osiam.resource_server.storage.entities.GroupEntity

import spock.lang.Specification

class ResourceUpdaterSpec extends Specification {

    static String IRRELEVANT = 'irrelevant'

    ResourceDao resourceDao = Mock()
    ResourceUpdater resourceUpdater = new ResourceUpdater(resourceDao: resourceDao)

    Meta metaWithAttributesToDelete = new Meta(attributes: ['externalId'] as Set)
    // resources are abstract so we use groups here with no loss of generality
    Group group
    GroupEntity groupEntity = Mock()

    def 'removing externalId works'() {
        given:
        group = new Group.Builder(meta: metaWithAttributesToDelete).build()

        when:
        resourceUpdater.update(group, groupEntity)

        then:
        1 * groupEntity.setExternalId(null)
    }

    def 'updating externalId works'() {
        given:
        def uuid = UUID.randomUUID()
        group = new Group.Builder(externalId: IRRELEVANT).build()
        groupEntity.getId() >> uuid

        when:
        resourceUpdater.update(group, groupEntity)

        then:
        1 * groupEntity.setExternalId(IRRELEVANT)
    }

    def 'updating the externalId checks if the externalId already exists' () {
        given:
        def uuid = UUID.randomUUID()
        Group group = new Group.Builder(externalId: IRRELEVANT).build()
        groupEntity.getId() >> uuid

        when:
        resourceUpdater.update(group, groupEntity)

        then:
        1 * resourceDao.isExternalIdAlreadyTaken(IRRELEVANT, uuid.toString())
    }

    def 'updating the externalId to an existing externalId raises exception' () {
        given:
        def uuid = UUID.randomUUID()
        Group group = new Group.Builder(externalId: IRRELEVANT).build()
        groupEntity.getId() >> uuid

        when:
        resourceUpdater.update(group, groupEntity)

        then:
        1 * resourceDao.isExternalIdAlreadyTaken(IRRELEVANT, uuid.toString()) >> true
        thrown(ResourceExistsException)
    }

}
