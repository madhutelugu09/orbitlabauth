package com.tm2space.firebase.orbitlabauth.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.jwt.JwtValidators;


import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public JwtDecoder jwtDecoder() {
        try {
            // Fetch the JWKS JSON from the URL
            URL url = new URL(jwkSetUri);
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jwks = objectMapper.readTree(url);

            Map<String, RSAPublicKey> publicKeys = new HashMap<>();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            // Iterate through the JSON object and parse each certificate
            Iterator<Map.Entry<String, JsonNode>> fields = jwks.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String kid = field.getKey();
                String certString = field.getValue().asText();
                X509Certificate certificate = parseCertificate(certString, certificateFactory);
                RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
                publicKeys.put(kid, publicKey);
            }

            
            // Create NimbusJwtDecoder with the extracted public keys
            NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKeys.get("d4269a1730e50719e6b1606e42c3ab32b1280449")).build();

            // Set the JWT validator with the issuer URI
            jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuerUri));

            return jwtDecoder;

        } catch (Exception e) {
            throw new RuntimeException("Failed to create JwtDecoder", e);
        }
    }

    private X509Certificate parseCertificate(String certString, CertificateFactory certificateFactory) throws Exception {
        String cleanCert = certString
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(cleanCert);
        return (X509Certificate) certificateFactory.generateCertificate(new java.io.ByteArrayInputStream(decoded));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/public/**").permitAll()  // Public endpoints
                .anyRequest().authenticated()  // Secure all other endpoints
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder()))
            )
            .sessionManagement(sessionManagement -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );
        return http.build();
    }
}
