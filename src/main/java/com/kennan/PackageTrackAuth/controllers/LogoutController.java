package com.kennan.PackageTrackAuth.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kennan.PackageTrackAuth.services.OAuthService;
import com.kennan.PackageTrackAuth.services.TokenService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@RestController
public class LogoutController {
    private final TokenService tokenService;
    private final OAuthService oAuthService;

    public LogoutController(TokenService tokenService, OAuthService oAuthService) {
        this.tokenService = tokenService;
        this.oAuthService = oAuthService;
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = oAuthService.getCookieValue(request, "access_token");
        String idToken = oAuthService.getCookieValue(request, "id_token");
        String refreshToken = oAuthService.getCookieValue(request, "refresh_token");

        tokenService.blackListToken(idToken);
        tokenService.revokeToken(accessToken);
        tokenService.revokeToken(refreshToken);

        oAuthService.removeHttpOnlyCookie("id_token", response);
        oAuthService.removeHttpOnlyCookie("refresh_token", response);
        oAuthService.removeHttpOnlyCookie("access_token", response);

        return ResponseEntity.ok("Logged out successfully");
    }
}
