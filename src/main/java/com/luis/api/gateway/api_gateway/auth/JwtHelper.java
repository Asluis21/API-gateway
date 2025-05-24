package com.luis.api.gateway.api_gateway.auth;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JwtHelper {
    
    private final String SECRET_KEY = "AEAEAEAEAEAEAEAEAEAEAEAEAEAEAAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEAE";

    public boolean validateToken(String token) {
        try {
            // Validate the token using the secret key
            Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY.getBytes())
                .build()
                .parseClaimsJws(token);

            return true;
        } catch (Exception e) {
            // Token is invalid

            System.out.println("Invalid JWT Token: " + e.getMessage());
            return false;
        }
    }

    public String getUsername(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(SECRET_KEY.getBytes())
            .build()
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    public List<String> getRoles(String token) {
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(SECRET_KEY.getBytes())
            .build()
            .parseClaimsJws(token)
            .getBody();
        Object rolesObject = claims.get("roles");
        
        if (rolesObject instanceof List<?>) {
            // If roles were stored as a JSON array
            return ((List<?>) rolesObject).stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .collect(Collectors.toList());
        } else if (rolesObject instanceof String) {
            // If roles were stored as a comma-separated String
            return Arrays.asList(((String) rolesObject).split(","));
        }
        return Collections.emptyList();
    }
}
