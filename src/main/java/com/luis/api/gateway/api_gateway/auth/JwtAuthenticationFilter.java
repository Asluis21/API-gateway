package com.luis.api.gateway.api_gateway.auth;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import lombok.AllArgsConstructor;
import reactor.core.publisher.Mono;

@AllArgsConstructor
@Component
public class JwtAuthenticationFilter implements WebFilter { 

    private final JwtHelper jwtHelper;
    
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private Mono<Void> onError(ServerWebExchange exchange, String error, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        log.error("JWT authentication error: " + error);
        return exchange.getResponse().setComplete();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        String token = request.getHeaders().getFirst(AUTHORIZATION_HEADER);
        String path = request.getURI().getPath();

        log.info("JWT Authentication Filter: " + token);
        log.info("Request Path: " + path);

        if(path.startsWith("/users/info")) {
            // Allow access to the /users/info endpoint without authentication
            return chain.filter(exchange);
        }

        if (token == null || !token.startsWith(BEARER_PREFIX)) {
            // If the token is null or does not start with "Bearer ", it means the user is not authenticated
            return onError(exchange, "Missing or invalid Authorization Header", HttpStatus.UNAUTHORIZED);
        }

        token = token.substring(BEARER_PREFIX.length());
        
        if(!jwtHelper.validateToken(token)) {
            // If the token is invalid, return an error response
            return onError(exchange, "Invalid JWT Token", HttpStatus.UNAUTHORIZED);
        }

        String username = jwtHelper.getUsername(token);
        List<GrantedAuthority> authorities = jwtHelper.getRoles(token)
            .stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());
        
        Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);

        return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
    }

}