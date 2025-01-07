package com.kennan.PackageTrackAuth.services;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class OAuthService {

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${google.token.url}")
    private String tokenUrl;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @Value("${google.oauth.url}")
    private String oauthUri;
   
    @Value("${spring.security.oauth2.client.registration.google.scope}")
    private String scope;

    private final RestTemplate restTemplate;

    public OAuthService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String generateState(HttpServletRequest request) {
        String redirectTo = request.getHeader("Origin") == null ? "https://www.google.com/" : request.getHeader("Origin");
        String secureState = UUID.randomUUID().toString();
        String statePayload = "{\"state\": \"" + secureState + "\", \"redirectTo\": \"" + redirectTo + "\"}";
        String encodedState = Base64.getEncoder().encodeToString(statePayload.getBytes());
        return encodedState;
    }

    public String validateState(String encodedState, HttpServletRequest request) {
        String encodedCookieState = getCookieValue(request, "state");
        
        if (encodedCookieState == null || !encodedCookieState.equals(encodedState)) {
            return null;
        }

        try {
            String decodedState = new String(Base64.getDecoder().decode(encodedState));
            
            return extractRedirectFromPayload(decodedState);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private String extractRedirectFromPayload(String decodedPayload) {
        int start = decodedPayload.indexOf("\"redirectTo\":") + 15;
        int end = decodedPayload.length() - 2;
        return (start > 12 && end > start) ? decodedPayload.substring(start, end) : null;
    }

    public String buildOAuthUri(String state, boolean withRefreshToken) {
        return oauthUri + "?" +
           "client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) + "&" +
           "redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8) + "&" +
           "response_type=code&" +
           "scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8) + "&" +
           "state=" + URLEncoder.encode(state, StandardCharsets.UTF_8) + "&" +
           "access_type=offline" +
           (withRefreshToken ? "&prompt=consent" : "");
    }

    public Map<String, String> retrieveAccessToken(String grant, boolean isRefresh) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("grant_type", isRefresh ? "refresh_token" : "authorization_code");
        if (isRefresh) {
            body.add("refresh_token", grant);
        } else {
            body.add("code", grant);
            body.add("redirect_uri", redirectUri);
        }

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
            tokenUrl,
            HttpMethod.POST,
            request,
            new ParameterizedTypeReference<Map<String, Object>>() {}
        );

        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("access_token", (String) response.getBody().get("access_token"));

        if (response.getBody().containsKey("refresh_token")) {
            tokenMap.put("refresh_token", (String) response.getBody().get("refresh_token"));
        }

        return tokenMap;
    }

    public void setHttpOnlyCookie(String token, String cookieName, HttpServletResponse response) {
        Cookie cookie = new Cookie(cookieName, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(3600);

        response.addCookie(cookie);
    }

    public void removeHttpOnlyCookie(String cookieName, HttpServletResponse response) {
        Cookie cookie = new Cookie(cookieName, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);

        response.addCookie(cookie);
    }

    public String getCookieValue(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(cookieName)) {
                return cookie.getValue();
            }
        }

        return null;
    }
}
