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

import org.osiam.resources.scim.Meta;
import org.osiam.resource_server.storage.entities.MetaEntity;
import org.springframework.stereotype.Service;

@Service
public class MetaConverter implements Converter<Meta, MetaEntity>{

    @Override
    public MetaEntity fromScim(Meta scim) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Meta toScim(MetaEntity entity) {
        if(entity == null){
            return null;
        }
        return new Meta.Builder(entity.getCreated(), entity.getLastModified())
                         .setResourceType(entity.getResourceType())
                         .build();
    }

   

}
