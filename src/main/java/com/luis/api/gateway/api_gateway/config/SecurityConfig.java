package com.luis.api.gateway.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.FormLoginSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.HttpBasicSpec;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.luis.api.gateway.api_gateway.auth.JwtAuthenticationFilter;

import lombok.AllArgsConstructor;

@AllArgsConstructor
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(exchanges -> exchanges

                // PUBLIC ENDPOINT
                .pathMatchers(HttpMethod.GET, "/healthMonitor/status").permitAll()
                
                // AUTHENTICATED ENDPOINT
                .pathMatchers(HttpMethod.GET, "/users/info/*").authenticated()
                
                // ROLE_ADMIN ENDPOINT
                .pathMatchers(HttpMethod.GET, "/users/stats").hasRole("ADMIN")
                
                .anyExchange().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .httpBasic(HttpBasicSpec::disable)
            .formLogin(FormLoginSpec::disable)
            .build();
    }
}
