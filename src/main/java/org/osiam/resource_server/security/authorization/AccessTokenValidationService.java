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

package org.osiam.resource_server.security.authorization;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.osiam.client.OsiamConnector;
import org.osiam.client.oauth.AccessToken;
import org.osiam.client.oauth.Scope;
import org.osiam.resources.scim.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Service;

@Service
public class AccessTokenValidationService implements ResourceServerTokenServices {

    @Value("${org.osiam.auth-server.home}")
    private String authServerHome;

    @Override
    public OAuth2Authentication loadAuthentication(String token) {
        AccessToken accessToken = validateAccessToken(token);

        Set<String> scopes = new HashSet<String>();
        if (accessToken.getScopes() != null) {
            for (Scope scope : accessToken.getScopes()) {
                scopes.add(scope.toString());
            }
        }

        // TODO, need more params
        OAuth2Request authRequest = new OAuth2Request(null, accessToken.getClientId(), null, true, scopes, null, null,
                null, null);

        Authentication auth = null;

        if (!accessToken.isClientOnly()) {
            User authUser = new User.Builder(accessToken.getUserName()).setId(accessToken.getUserId()).build();

            auth = new UsernamePasswordAuthenticationToken(authUser, null, new ArrayList<GrantedAuthority>());
        }

        return new OAuth2Authentication(authRequest, auth);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String token) {
        AccessToken accessToken = validateAccessToken(token);

        Set<String> scopes = new HashSet<String>();
        for (Scope scope : accessToken.getScopes()) {
            scopes.add(scope.toString());
        }

        DefaultOAuth2AccessToken oAuth2AccessToken = new DefaultOAuth2AccessToken(token);
        oAuth2AccessToken.setScope(scopes);
        oAuth2AccessToken.setExpiration(accessToken.getExpiresAt());
        oAuth2AccessToken.setTokenType("BEARER");

        return oAuth2AccessToken;
    }

    /**
     * Revokes the access tokens of the user with the given ID.
     * 
     * @param id
     *            the user ID
     * @param token
     *            the token to access the service
     */
    public void revokeAccessTokens(String id, String token) {
        AccessToken accessToken = new AccessToken.Builder(token).build();
        OsiamConnector connector = createConnector();
        connector.revokeAllAccessTokens(id, accessToken);
    }

    private AccessToken validateAccessToken(String token) {
        OsiamConnector connector = createConnector();

        AccessToken accessToken = null;
        try {
            accessToken = connector.validateAccessToken(new AccessToken.Builder(token).build());
        } catch (Exception e) {
            throw new InvalidTokenException("Your token is not valid");
        }
        return accessToken;
    }

    private OsiamConnector createConnector() {
        OsiamConnector.Builder oConBuilder = new OsiamConnector.Builder().
                setAuthServerEndpoint(authServerHome);
        return oConBuilder.build();
    }
}