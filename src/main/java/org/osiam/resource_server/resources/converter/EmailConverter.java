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

package org.osiam.resource_server.resources.converter;

import org.osiam.resources.scim.Email;
import org.osiam.resource_server.storage.entities.EmailEntity;
import org.springframework.stereotype.Service;

@Service
public class EmailConverter implements Converter<Email, EmailEntity> {

    @Override
    public EmailEntity fromScim(Email scim) {
        EmailEntity emailEntity = new EmailEntity();
        emailEntity.setValue(scim.getValue());
        emailEntity.setPrimary(scim.isPrimary());
        emailEntity.setType(scim.getType());

        return emailEntity;
    }

    @Override
    public Email toScim(EmailEntity entity) {
        return new Email.Builder()
                .setPrimary(entity.isPrimary())
                .setType(entity.getType())
                .setValue(entity.getValue())
                .build();
    }

}
