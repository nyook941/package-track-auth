package com.kennan.PackageTrackAuth.controllers;

import java.io.IOException;
import java.util.Map;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import com.kennan.PackageTrackAuth.models.User;
import com.kennan.PackageTrackAuth.services.OAuthService;
import com.kennan.PackageTrackAuth.services.TokenService;
import com.kennan.PackageTrackAuth.services.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@RequestMapping("/oauth")
@RestController
public class OAuthController {
    private final OAuthService oAuthService;
    private final UserService userService;
    private final TokenService tokenService;

    public OAuthController(OAuthService oAuthService, UserService userService, TokenService tokenService) {
        this.oAuthService = oAuthService;
        this.userService = userService;
        this.tokenService = tokenService;
    }

    @GetMapping("/authorize")
    public RedirectView redirectToOAuthProvider(HttpServletRequest request, HttpServletResponse response) {
        boolean withRefreshToken = request.getParameter("refresh") != null;
        String encodedState = oAuthService.generateState(request);
        oAuthService.setHttpOnlyCookie(encodedState, "state", response);

        String oAuthUri = oAuthService.buildOAuthUri(encodedState, withRefreshToken);
        return new RedirectView(oAuthUri);
    }

    @GetMapping("/callback")
    public void handleOAuthCallback(@RequestParam String code, 
                                    @RequestParam String state,
                                    HttpServletRequest request,
                                    HttpServletResponse response
    ) throws IOException {
        String redirect = oAuthService.validateState(state, request);
        if (redirect == null){
            response.sendRedirect("/");
            return;
        }

        Map<String, String> tokensMap = oAuthService.retrieveAccessToken(code, false);
        String accessToken = tokensMap.get("access_token");
        if (tokensMap.containsKey("refresh_token")) {
            String refreshToken = tokensMap.get("refresh_token");
            oAuthService.setHttpOnlyCookie(refreshToken, "refresh_token", response);
        }

        User user = userService.createUser(accessToken);
        Jwt idToken = tokenService.generateJwt(user);

        oAuthService.setHttpOnlyCookie(idToken.getTokenValue(), "id_token", response);
        oAuthService.setHttpOnlyCookie(accessToken, "access_token", response);
        response.sendRedirect(redirect);
    }
}
