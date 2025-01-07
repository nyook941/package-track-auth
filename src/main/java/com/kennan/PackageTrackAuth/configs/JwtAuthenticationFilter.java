package com.kennan.PackageTrackAuth.configs;

import java.io.IOException;

import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import com.kennan.PackageTrackAuth.models.User;
import com.kennan.PackageTrackAuth.repositories.UserRepository;
import com.kennan.PackageTrackAuth.services.OAuthService;
import com.kennan.PackageTrackAuth.services.TokenService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final HandlerExceptionResolver handlerExceptionResolver;
    private final UserRepository userRepository;
    private final OAuthService oAuthService;

    private final ApplicationContext applicationContext;
    private TokenService tokenService;

    public JwtAuthenticationFilter(
        HandlerExceptionResolver handlerExceptionResolver,
        UserRepository userRepository,
        OAuthService oAuthService,
        ApplicationContext applicationContext
    ) {
        this.handlerExceptionResolver = handlerExceptionResolver;
        this.userRepository = userRepository;
        this.oAuthService = oAuthService;
        this.applicationContext = applicationContext;
    }

    private TokenService getTokenService() {
        if (this.tokenService == null) {
            this.tokenService = applicationContext.getBean(TokenService.class);
        }
        return this.tokenService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String[] excludedPaths = {"/oauth/**", "/token/**", "/error/**"};
        AntPathMatcher pathMatcher = new AntPathMatcher();

        for (String path : excludedPaths) {
            if (pathMatcher.match(path, request.getServletPath())) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        final String idToken = oAuthService.getCookieValue(request, "id_token");

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null || idToken == null) {
                filterChain.doFilter(request, response);
                return;
            }

            Jwt jwt = getTokenService().validateJwt(idToken);
            if (jwt == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid or expired token");
                response.getWriter().flush();
                return;
            }

            final String userId = jwt.getClaim("sub");
            final User user = userRepository.findById(userId).orElse(null);
            if (user != null) {
                UserAuthenticationToken userAuthenticationToken = new UserAuthenticationToken(userId, user.getRole());
                SecurityContextHolder.getContext().setAuthentication(userAuthenticationToken);
            }

            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            handlerExceptionResolver.resolveException(request, response, null, exception);
        }
    }
}

