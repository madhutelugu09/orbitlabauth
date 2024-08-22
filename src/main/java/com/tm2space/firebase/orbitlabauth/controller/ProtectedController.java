package com.tm2space.firebase.orbitlabauth.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/protected")
public class ProtectedController {

    @GetMapping("/hello")
    public String helloProtected(@AuthenticationPrincipal Jwt jwt) {
        // You can access JWT claims here if needed
        String userName = jwt.getClaim("phone_number");
        return "Hello, " + userName + "! This is a protected endpoint. Your JWT is valid.";
    }
}
