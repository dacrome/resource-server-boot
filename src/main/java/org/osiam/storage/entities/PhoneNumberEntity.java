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

import javax.persistence.*;

/**
 * Phone Numbers Entity
 */
@Entity
@Table(name = "scim_phoneNumber")
public class PhoneNumberEntity extends MultiValueAttributeEntitySkeleton implements ChildOfMultiValueAttributeWithIdAndType, HasUser {

    @Column
    @Enumerated(EnumType.STRING)
    private CanonicalPhoneNumberTypes type;

    @ManyToOne
    private UserEntity user;

    @Override
    public String getType() {
        if (type != null) {
            return type.toString();
        }
        return null;
    }

    @Override
    public void setType(String type) {
        if (type != null) {
            this.type = CanonicalPhoneNumberTypes.valueOf(type);
        }
    }

    @Override
    public UserEntity getUser() {
        return user;
    }

    @Override
    public void setUser(UserEntity user) {
        this.user = user;
    }

    public enum CanonicalPhoneNumberTypes {
        work, home, mobile, fax, pager, other
    }
}