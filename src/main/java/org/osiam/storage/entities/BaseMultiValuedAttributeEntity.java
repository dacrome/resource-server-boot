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

package org.osiam.storage.entities;

import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.MappedSuperclass;
import javax.persistence.SequenceGenerator;

@MappedSuperclass
public abstract class BaseMultiValuedAttributeEntity {

    @Id
    @SequenceGenerator(name = "sequence_scim_multi_valued_attribute",
            sequenceName = "resource_server_sequence_scim_multi_valued_attribute",
            allocationSize = 1,
            initialValue = 100)
    @GeneratedValue(generator = "sequence_scim_multi_valued_attribute")
    @Column(name = "multi_value_id")
    private long multiValueId;

    @Column(name = "is_primary")
    private Boolean primary;

    public void setMultiValueId(long id) {
        this.multiValueId = id;
    }

    public long getMultiValueId() {
        return multiValueId;
    }

    public boolean isPrimary() {
        if (primary == null) {
            return false;
        }
        return primary;
    }

    public void setPrimary(boolean primary) {
        this.primary = primary;
    }

}
