package com.kennan.PackageTrackAuth.controllers;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kennan.PackageTrackAuth.services.OAuthService;
import com.kennan.PackageTrackAuth.services.TokenService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RequestMapping("/token")
@RestController
public class TokenController {
    private final TokenService tokenService;
    private final OAuthService oAuthService;

    TokenController(TokenService tokenService, OAuthService oAuthService) {
        this.tokenService = tokenService;
        this.oAuthService = oAuthService;
    }

    @PostMapping("/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = oAuthService.getCookieValue(request, "refresh_token");
        if (refreshToken == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        Map<String, String> tokenMap = oAuthService.retrieveAccessToken(refreshToken, true);
        String accessToken = tokenMap.get("access_token");
        
        oAuthService.setHttpOnlyCookie(accessToken, "access_token", response);
    }

    @PostMapping("/id/introspect")
    public ResponseEntity<Boolean> introspectToken(HttpServletRequest request) {
        try {
            String authorizationHeader = request.getHeader("Authorization");
            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                return ResponseEntity.badRequest().body(false);
            }

            String idToken = authorizationHeader.substring(7);
            Jwt jwt = tokenService.validateJwt(idToken);
            return ResponseEntity.ok(jwt != null);
        } catch (JwtException e) {
            return ResponseEntity.ok(false);
        }
    }

    @PostMapping("/access/introspect")
    public ResponseEntity<Boolean> introspectAccessToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(false);
        }

        String accessToken = authorizationHeader.substring(7);
        String validatedToken = tokenService.validateAccessToken(accessToken);
        return ResponseEntity.ok(validatedToken != null);
    }
}
