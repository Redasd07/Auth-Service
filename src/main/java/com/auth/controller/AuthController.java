package com.auth.controller;

import com.auth.dto.LoginRequest;
import com.auth.dto.RegisterRequest;
import com.auth.dto.ResetPasswordRequest;
import com.auth.dto.VerifyEmailRequest;
import com.auth.dto.UserDTO;
import com.auth.exception.CustomException;
import com.auth.service.AuthService;
import com.auth.utils.DtoConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private DtoConverter dtoConverter;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            var user = authService.register(request);
            return ResponseEntity.ok(dtoConverter.toUserDTO(user));
        } catch (CustomException ex) {
            return ResponseEntity.status(ex.getStatus()).body(ex.getMessage());
        }
    }


    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestBody VerifyEmailRequest request) {
        authService.verifyEmail(request);
        return ResponseEntity.ok("Email vérifié avec succès.");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            var response = authService.loginWithDetails(request);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            if ("OTP required.".equals(e.getMessage())) {
                return ResponseEntity.status(202).body("OTP required.");
            }
            throw e;
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestParam String email, @RequestParam String otpCode) {
        authService.verifyOtp(email, otpCode);
        return ResponseEntity.ok("2FA validée avec succès.");
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(@RequestParam String email) {
        authService.generateAndSendOtp(email);
        return ResponseEntity.ok("OTP renvoyé avec succès.");
    }


    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        authService.forgotPassword(email);
        return ResponseEntity.ok("Un lien de réinitialisation a été envoyé à votre adresse email.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(token, request);
        return ResponseEntity.ok("Mot de passe réinitialisé avec succès.");
    }

    @GetMapping("/me")
    public ResponseEntity<UserDTO> getCurrentUser() {
        String email = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        UserDTO userDTO = authService.getUserDetails(email);
        return ResponseEntity.ok(userDTO);
    }
}
