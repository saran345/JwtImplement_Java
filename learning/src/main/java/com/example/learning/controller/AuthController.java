package com.example.learning.controller;

import com.example.learning.dto.LoginDto;
import com.example.learning.dto.RegisterDto;

import com.example.learning.model.User;
import com.example.learning.repository.UserRepository;
import com.example.learning.service.Jwtutils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository repo;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private AuthenticationManager manager;

    @Autowired
    private Jwtutils jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterDto dto) {
        if (repo.findByUsername(dto.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }

        User user = new User();
        user.setUsername(dto.getUsername());
        user.setPassword(encoder.encode(dto.getPassword()));

        // Set role with "ROLE_" prefix
        String inputRole = dto.getRole().toUpperCase();
        if (!inputRole.equals("ADMIN") && !inputRole.equals("USER")) {
            return ResponseEntity.badRequest().body("Invalid role. Use 'USER' or 'ADMIN'");
        }

        user.setRole("ROLE_" + inputRole);
        repo.save(user);
        return ResponseEntity.ok("User registered successfully as " + user.getRole());
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDto dto) {
        try {
            Authentication auth = manager.authenticate(
                    new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword()));

            User user = repo.findByUsername(dto.getUsername()).orElseThrow();
            String token = jwtUtil.generateToken(dto.getUsername());

            return ResponseEntity.ok(new TokenResponse(token, user.getRole()));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    // Record for JWT + Role response
    record TokenResponse(String token, String role) {}
}
