package com.kennan.PackageTrackAuth.services;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.kennan.PackageTrackAuth.models.User;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Service
public class TokenService {
    @Value("${google.token.info.url}")
    private String tokenUrl;

    @Value("${google.token.revoke.url}")
    private String revokeUrl;

    @Value("${jwt.secret}")
    private String jwtSecret;

    private final NimbusJwtDecoder jwtDecoder;
    private final RestTemplate restTemplate;

    private final RedisTemplate<String, String> redisTemplate;
    private static String BLACK_LIST_PREFIX = "blacklisted:";

    public TokenService(NimbusJwtDecoder jwtDecoder, RestTemplate restTemplate, RedisTemplate<String, String> redisTemplate) {
        this.jwtDecoder = jwtDecoder;
        this.restTemplate = restTemplate;
        this.redisTemplate = redisTemplate;
    }

    public Jwt validateJwt(String token) throws JwtException{
        if (isTokenBlackListed(token)) {
            throw new JwtException("Token is blacklisted");
        }
        return jwtDecoder.decode(token);
    }

    public Jwt generateJwt(User user) {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user.getId())
                .issuer("package-track-auth")
                .claim("id", user.getId())
                .claim("role", user.getRole())
                .build();

            SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.HS256),
                claims    
            );
            signedJWT.sign(new MACSigner(jwtSecret));
            Jwt jwt = validateJwt(signedJWT.serialize());
            return jwt;
        } catch(Exception exception) {
            throw new JwtException("Failed to generate JWT:" + exception);
        }
    }

    public String validateAccessToken(String token) {
        String url = tokenUrl + "?access_token=" + token;
        try{
            return restTemplate.getForObject(url, String.class);
        } catch (Exception e) {
            return null;
        }
    }

    public String revokeToken(String token) {
        String url = revokeUrl + "?token=" + token;
        try{
            return restTemplate.getForObject(url, String.class);
        } catch (Exception e) {
            return null;
        }
    }

    public String blackListToken(String tokenId) {
        Jwt jwt = jwtDecoder.decode(tokenId);

        long expirationSeconds = jwt.getExpiresAt().toEpochMilli() / 1000;

        long currentTimeSeconds = System.currentTimeMillis() / 1000;

        long ttlSeconds = expirationSeconds - currentTimeSeconds;

        if (ttlSeconds > 0) {
            String key = BLACK_LIST_PREFIX + tokenId;
            redisTemplate.opsForValue().set(key, tokenId);
            redisTemplate.expire(key, ttlSeconds, TimeUnit.SECONDS);
        } else {
            throw new IllegalArgumentException("JWT is already expired and cannot be blacklisted.");
        }

        return tokenId;
    }

    public boolean isTokenBlackListed(String tokenId) {
        String key = BLACK_LIST_PREFIX + tokenId;
        return redisTemplate.hasKey(key);
    }
}
