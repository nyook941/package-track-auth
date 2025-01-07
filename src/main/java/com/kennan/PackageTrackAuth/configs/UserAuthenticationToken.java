package com.kennan.PackageTrackAuth.configs;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

public class UserAuthenticationToken extends AbstractAuthenticationToken {
    private final String userId;

    public UserAuthenticationToken(String userId, String role) {
        super(AuthorityUtils.createAuthorityList(role));
        this.userId = userId;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return userId;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }
    
}
