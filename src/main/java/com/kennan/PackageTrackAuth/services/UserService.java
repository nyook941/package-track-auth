package com.kennan.PackageTrackAuth.services;

import java.util.Base64;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.kennan.PackageTrackAuth.models.User;
import com.kennan.PackageTrackAuth.repositories.UserRepository;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final RestTemplate restTemplate;

    @Value("${google.gmail.profile.info.url}")
    private String profileInfoUrl;

    @Value("${email.encryption.key}")
    private String emailEncryptionKey;

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public UserService(UserRepository userRepository, RestTemplate restTemplate) {
        this.userRepository = userRepository;
        this.restTemplate = restTemplate;
    }

    public User createUser(String accessToken) {
        String email = fetchEmail(accessToken);
        String userId = hashEmail(email);

        User user = new User();
        user.setId(userId);
        user.setOAuthProvider("google");
        user.setRole("ROLE_USER");
        return userRepository.save(user);
    }

    public String fetchEmail(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    profileInfoUrl,
                    org.springframework.http.HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
                );
        Map<String, Object> profileInfo = response.getBody();
        return (String) profileInfo.get("emailAddress");
    }

    public String hashEmail(String email) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(emailEncryptionKey.getBytes(), HMAC_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(email.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hmacBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing email", e);
        }
    }
    
}
