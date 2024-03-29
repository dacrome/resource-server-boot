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

package org.osiam.resource_server.storage.entities;

import javax.persistence.Basic;
import javax.persistence.Entity;
import javax.persistence.Index;
import javax.persistence.Table;

import org.osiam.resources.scim.Role;

/**
 * Roles Entity
 */
@Entity
@Table(name = "scim_roles",
        indexes = {
                @Index(columnList = "value"),
                @Index(columnList = "type"),
                @Index(columnList = "value, type"),
        })
public class RoleEntity extends BaseMultiValuedAttributeEntityWithValue {

    /**
     * <p>
     * The type of this Role.
     * </p>
     * 
     * <p>
     * Custom type mapping is provided by {@link org.osiam.resource_server.storage.entities.jpa_converters.RoleTypeConverter}.
     * </p>
     */
    @Basic
    private Role.Type type; // @Basic is needed for JPA meta model generator

    public Role.Type getType() {
        return type;
    }

    public void setType(Role.Type type) {
        this.type = type;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        RoleEntity other = (RoleEntity) obj;
        if (type == null) {
            if (other.type != null) {
                return false;
            }
        } else if (!type.equals(other.type)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "RolesEntity [value=" + getValue() + ", primary=" + isPrimary() + "]";
    }

}