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

import com.google.common.collect.ImmutableSet;
import org.osiam.resources.scim.Group;
import org.osiam.resources.scim.MultiValuedAttribute;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ManyToMany;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Group Entity
 */
@Entity(name = "scim_group")
public class GroupEntity extends InternalIdSkeleton {

    private static final long serialVersionUID = -6535056565639057158L;

    @ManyToMany(fetch = FetchType.EAGER)
    private Set<InternalIdSkeleton> members = new HashSet<>();

    @Column(unique = true, nullable = false)
    private String displayName;

    public GroupEntity() {
        getMeta().setResourceType("Group");
    }

    private static Set<InternalIdSkeleton> createMembers(Group group) {
        Set<InternalIdSkeleton> result = new HashSet<>();
        if (group.getMembers() != null) {
            transferMultiValueAttributeToInternalIdSkeleton(group, result);
        }

        return result;
    }

    private static void transferMultiValueAttributeToInternalIdSkeleton(Group group, Set<InternalIdSkeleton> result) {
        for (final MultiValuedAttribute m : group.getMembers()) {
            InternalIdSkeleton skeleton = new InternalIdSkeletonToMultivalueAttribute(m.getDisplay(), UUID.fromString(String.valueOf(m.getValue())));
            result.add(skeleton);
        }
    }

    private static class InternalIdSkeletonToMultivalueAttribute extends InternalIdSkeleton {

        private static final long serialVersionUID = 2192883719672334983L;
        private final String displayName;

        public InternalIdSkeletonToMultivalueAttribute(String displayName, UUID uuid) {
            this.displayName = displayName;
            setId(uuid);
        }

        @Override
        public String getDisplayName() {
            return displayName;
        }

        
        public <T> T toScim() {
            return null;
        }
    }

    public Set<InternalIdSkeleton> getMembers() {
        return ImmutableSet.copyOf(members);
    }

    public void addMember(InternalIdSkeleton member) {
        if (members.contains(member)) {
            return;
        }
        this.members.add(member);
        member.addToGroup(this);
    }

    public void removeMember(InternalIdSkeleton member) {
        if (!members.contains(member)) {
            return;
        }
        members.remove(member);
        member.removeFromGroup(this);
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        return super.equals(other);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

    private Set<MultiValuedAttribute> membersToScim() {
        Set<MultiValuedAttribute> members1 = new HashSet<>();
        for (InternalIdSkeleton i : members) {
            members1.add(
                    new MultiValuedAttribute.Builder().setValue(i.getId().toString()).setDisplay(i.getDisplayName())
                            .build());
        }
        return members1;
    }

    @Override
    public String toString() {
        return "GroupEntity{" +
                "UUID='" + getId() + "\', " +
                "displayName='" + displayName + '\'' +
                '}';
    }
}