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

import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import com.google.common.collect.ImmutableSet;

/**
 * User Entity
 */
@Entity
@Table(name = "scim_user")
public class UserEntity extends ResourceEntity {

    private static final String JOIN_COLUMN_NAME = "user_internal_id";

    @Column(nullable = false, unique = true)
    private String userName;

    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
    private NameEntity name;

    @Column
    private String nickName;

    @Column
    private String profileUrl;

    @Column
    private String title;

    @Column
    private String userType;

    @Column
    private String preferredLanguage;

    @Column
    private String locale;

    @Column
    private String timezone;

    @Column
    private Boolean active = Boolean.FALSE;

    @Column(nullable = false)
    private String password;

    @Column
    private String displayName;

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = JOIN_COLUMN_NAME)
    private Set<EmailEntity> emails = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = JOIN_COLUMN_NAME)
    private Set<PhoneNumberEntity> phoneNumbers = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = JOIN_COLUMN_NAME)
    private Set<ImEntity> ims = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = JOIN_COLUMN_NAME)
    private Set<PhotoEntity> photos = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = JOIN_COLUMN_NAME)
    private Set<AddressEntity> addresses = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = JOIN_COLUMN_NAME)
    private Set<EntitlementsEntity> entitlements = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = JOIN_COLUMN_NAME)
    private Set<RolesEntity> roles = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = JOIN_COLUMN_NAME)
    private Set<X509CertificateEntity> x509Certificates = new HashSet<>();

    // TODO: fix relationship or delete it (it is not used right now)
    @OneToMany
    @JoinTable(name = "scim_user_scim_extension", joinColumns = { @JoinColumn(name = "scim_user_internal_id", referencedColumnName = "internal_id") },
            inverseJoinColumns = { @JoinColumn(name = "registered_extensions_internal_id", referencedColumnName = "internal_id") })
    private Set<ExtensionEntity> registeredExtensions = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = JOIN_COLUMN_NAME)
    private Set<ExtensionFieldValueEntity> extensionFieldValues = new HashSet<>();

    public UserEntity() {
        getMeta().setResourceType("User");
    }

    /**
     * @return the name entity
     */
    public NameEntity getName() {
        return name;
    }

    /**
     * @param name
     *            the name entity
     */
    public void setName(NameEntity name) {
        this.name = name;
    }

    /**
     * @return the nick name
     */
    public String getNickName() {
        return nickName;
    }

    /**
     * @param nickName
     *            the nick name
     */
    public void setNickName(String nickName) {
        this.nickName = nickName;
    }

    /**
     * @return the profile url
     */
    public String getProfileUrl() {
        return profileUrl;
    }

    /**
     * @param profileUrl
     *            the profile url
     */
    public void setProfileUrl(String profileUrl) {
        this.profileUrl = profileUrl;
    }

    /**
     * @return the title
     */
    public String getTitle() {
        return title;
    }

    /**
     * @param title
     *            the title
     */
    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * @return the user type
     */
    public String getUserType() {
        return userType;
    }

    /**
     * @param userType
     *            the user type
     */
    public void setUserType(String userType) {
        this.userType = userType;
    }

    /**
     * @return the preferred languages
     */
    public String getPreferredLanguage() {
        return preferredLanguage;
    }

    /**
     * @param preferredLanguage
     *            the preferred languages
     */
    public void setPreferredLanguage(String preferredLanguage) {
        this.preferredLanguage = preferredLanguage;
    }

    /**
     * @return the locale
     */
    public String getLocale() {
        return locale;
    }

    /**
     * @param locale
     *            the locale
     */
    public void setLocale(String locale) {
        this.locale = locale;
    }

    /**
     * @return the timezone
     */
    public String getTimezone() {
        return timezone;
    }

    /**
     * @param timezone
     *            the timezone
     */
    public void setTimezone(String timezone) {
        this.timezone = timezone;
    }

    /**
     * @return the active status
     */
    public Boolean getActive() {
        return active;
    }

    /**
     * @param active
     *            the active status
     */
    public void setActive(Boolean active) {
        this.active = active;
    }

    /**
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * @param password
     *            the password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getUserName() {
        return userName;
    }

    /**
     * @param userName
     *            the user name
     */
    public void setUserName(String userName) {
        this.userName = userName;
    }

    /**
     * Returns an immutable view of the list of emails
     *
     * @return the emails entity
     */
    public Set<EmailEntity> getEmails() {
        return ImmutableSet.copyOf(emails);
    }

    /**
     * Adds a new email to this user
     *
     * @param email
     *            the emai lto add
     */
    public void addEmail(EmailEntity email) {
        emails.add(email);
    }

    /**
     * Removes the given email from this user
     *
     * @param email
     *            the email to remove
     */
    public void removeEmail(EmailEntity email) {
        emails.remove(email);
    }

    /**
     * @param emails
     *            the emails entity
     * @deprecated
     */
    @Deprecated
    public void setEmails(Set<EmailEntity> emails) {
        this.emails = emails;
    }

    /**
     * @return the extensions data of the user
     */
    public Set<ExtensionFieldValueEntity> getUserExtensions() {
        if (extensionFieldValues == null) {
            extensionFieldValues = new HashSet<>();
        }
        return extensionFieldValues;
    }

    /**
     * @param userExtensions
     *            the extension data of the user
     */
    public void setUserExtensions(Set<ExtensionFieldValueEntity> userExtensions) {
        if (userExtensions != null) {
            for (ExtensionFieldValueEntity extensionValue : userExtensions) {
                extensionValue.setUser(this);
            }
        }
        this.extensionFieldValues = userExtensions;
    }

    /**
     * @return the phone numbers entity
     */
    public Set<PhoneNumberEntity> getPhoneNumbers() {
        return phoneNumbers;
    }

    /**
     * @param phoneNumbers
     *            the phone numbers entity
     */
    public void setPhoneNumbers(Set<PhoneNumberEntity> phoneNumbers) {
        this.phoneNumbers = phoneNumbers;
    }

    /**
     * @return the instant messaging entity
     */
    public Set<ImEntity> getIms() {
        return ims;
    }

    /**
     * @param ims
     *            the instant messaging entity
     */
    public void setIms(Set<ImEntity> ims) {
        this.ims = ims;
    }

    /**
     * @return the photos entity
     */
    public Set<PhotoEntity> getPhotos() {
        return photos;
    }

    /**
     * @param photos
     *            the photos entity
     */
    public void setPhotos(Set<PhotoEntity> photos) {
        this.photos = photos;
    }

    /**
     * @return the addresses entity
     */
    public Set<AddressEntity> getAddresses() {
        return addresses;
    }

    /**
     * @param addresses
     *            the addresses entity
     */
    public void setAddresses(Set<AddressEntity> addresses) {
        this.addresses = addresses;
    }

    /**
     * @return the entitlements
     */
    public Set<EntitlementsEntity> getEntitlements() {
        return entitlements;
    }

    /**
     * @param entitlements
     *            the entitlements
     */
    public void setEntitlements(Set<EntitlementsEntity> entitlements) {
        this.entitlements = entitlements;
    }

    /**
     * @return the roles
     */
    public Set<RolesEntity> getRoles() {
        return roles;
    }

    /**
     * @param roles
     *            the roles
     */
    public void setRoles(Set<RolesEntity> roles) {
        this.roles = roles;
    }

    /**
     * @return the X509 certs
     */
    public Set<X509CertificateEntity> getX509Certificates() {
        return x509Certificates;
    }

    /**
     * @param x509Certificates
     *            the X509 certs
     */
    public void setX509Certificates(Set<X509CertificateEntity> x509Certificates) {
        this.x509Certificates = x509Certificates;
    }

    /**
     * Registers a new extension for this User. If the given extension is already registered, it will be ignored.
     *
     * @param extension
     *            The extension to register
     */
    public void registerExtension(ExtensionEntity extension) {
        if (extension == null) {
            throw new IllegalArgumentException("extension must not be null");
        }

        registeredExtensions.add(extension);
    }

    /**
     * Read all registered user extensions.
     *
     * @return A set of all registered user extensions. Never null;
     */
    public Set<ExtensionEntity> getRegisteredExtensions() {
        return registeredExtensions;
    }

    /**
     * Adds or updates an extension field value for this User. When updating, the old value of the extension field is
     * removed from this user and the new one will be added.
     *
     * @param extensionValue
     *            The extension field value to add or update
     */
    public void addOrUpdateExtensionValue(ExtensionFieldValueEntity extensionValue) {
        if (extensionValue == null) {
            throw new IllegalArgumentException("extensionValue must not be null");
        }

        if (extensionFieldValues.contains(extensionValue)) {
            extensionFieldValues.remove(extensionValue);
        }

        extensionValue.setUser(this);

        extensionFieldValues.add(extensionValue);
    }

    @Override
    public String toString() {
        return "UserEntity{" +
                "UUID='" + getId() + "\', " +
                "userName='" + userName + '\'' +
                '}';
    }
}
