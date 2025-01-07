package com.kennan.PackageTrackAuth.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class ApplicationConfiguration {
    public ApplicationConfiguration() {
        
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
