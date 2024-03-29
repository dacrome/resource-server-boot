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

package org.osiam.resource_server.storage.entities

import spock.lang.Specification

class UserExtensionSpec extends Specification {

    UserEntity userEntity = new UserEntity()

    def "If extensions are null empty set should be returned"() {
        when:
        def emptySet = userEntity.getExtensionFieldValues()

        then:
        emptySet != null
    }

    def 'adding a field value works'() {
        given:
        def extension = new ExtensionEntity()

        def extensionField = new ExtensionFieldEntity()
        extensionField.extension = extension
        extensionField.name = "testField"

        def fieldValue = new ExtensionFieldValueEntity()

        when:
        userEntity.addOrUpdateExtensionValue(fieldValue)

        then:
        userEntity.extensionFieldValues.contains(fieldValue)
    }

    def 'adding null as extension value raises exception'() {
        given:
        def extension = new ExtensionEntity()

        when:
        userEntity.addOrUpdateExtensionValue(null)

        then:
        thrown(IllegalArgumentException)
    }

    def 'updating an extension value works'() {
        given:
        def extension = new ExtensionEntity()

        def extensionField = new ExtensionFieldEntity()
        extensionField.extension = extension
        extensionField.name = "testField"

        def fieldValue = new ExtensionFieldValueEntity(extensionField: extensionField, value: "fieldValue")

        def fieldValueUpdated = new ExtensionFieldValueEntity(extensionField: extensionField, value: "fieldValueUpdated")

        userEntity.addOrUpdateExtensionValue(fieldValue)

        when:
        userEntity.addOrUpdateExtensionValue(fieldValueUpdated)

        then:
        extensionValuesOnlyContains(fieldValueUpdated, extensionField)
    }

    def extensionValuesOnlyContains(fieldValue, extensionField) {
        def ok = false
        for (extensionFieldValue in userEntity.extensionFieldValues) {
            if (extensionFieldValue.extensionField != extensionField) {
                continue
            }

            if (extensionFieldValue.value == fieldValue.value) {
                ok = true
                continue
            } else {
                ok = false
                break
            }
        }
        ok
    }
}
