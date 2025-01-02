package com.auth.controller;

import com.auth.dto.*;
import com.auth.entity.User;
import com.auth.exception.CustomException;
import com.auth.service.AuthService;
import com.auth.utils.DtoConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final DtoConverter dtoConverter;

    @Autowired
    public AuthController(AuthService authService, DtoConverter dtoConverter) {
        this.authService = authService;
        this.dtoConverter = dtoConverter;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            var user = authService.register(request);
            String verificationToken = authService.generateEmailVerificationToken(user.getEmail());
            return ResponseEntity.ok(Map.of(
                    "user", dtoConverter.toUserDTO(user),
                    "verificationToken", verificationToken
            ));
        } catch (CustomException ex) {
            return ResponseEntity.status(ex.getStatus()).body(Map.of("error", ex.getMessage()));
        }
    }

    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestBody VerifyEmailRequest request) {
        try {
            authService.verifyEmailWithToken(request.getVerificationToken(), request.getOtpCode());
            return ResponseEntity.ok(Map.of("message", "Email verified successfully."));
        } catch (CustomException e) {
            return ResponseEntity.status(e.getStatus()).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(@RequestBody Map<String, String> request) {
        try {
            String verificationToken = request.get("verificationToken");
            String context = request.get("context"); // "EMAIL_VERIFICATION", "RESET_PASSWORD", or "2FA"

            authService.resendOtp(verificationToken, context);

            return ResponseEntity.ok(Map.of("message", "OTP resent successfully."));
        } catch (CustomException e) {
            return ResponseEntity.status(e.getStatus()).body(Map.of("error", e.getMessage()));
        }
    }



    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            var response = authService.loginWithDetails(request);
            return ResponseEntity.ok(response);
        } catch (CustomException e) {
            if ("Email is not verified".equals(e.getMessage())) {
                User user = authService.getUserByEmail(request.getEmail());
                authService.resendEmailVerificationOtp(user.getVerificationToken()); // Envoyer l'OTP par email
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of(
                                "error", "Email is not verified",
                                "verificationToken", user.getVerificationToken()
                        ));
            }
            if ("OTP required".equals(e.getMessage())) {
                return ResponseEntity.status(HttpStatus.ACCEPTED)
                        .body(Map.of(
                                "error", "OTP required",
                                "verificationToken", e.getAdditionalData().get("verificationToken")
                        ));
            }
            return ResponseEntity.status(e.getStatus()).body(Map.of("error", e.getMessage()));
        }
    }


    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            String verificationToken = authService.forgotPassword(email);
            return ResponseEntity.ok(Map.of(
                    "message", "An OTP has been sent to your email for password reset.",
                    "verificationToken", verificationToken
            ));
        } catch (CustomException e) {
            if ("Email is not verified".equals(e.getMessage())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of(
                                "error", "Email is not verified",
                                "verificationToken", e.getAdditionalData().get("verificationToken"),
                                "message", e.getAdditionalData().get("message")
                        ));
            }
            return ResponseEntity.status(e.getStatus()).body(Map.of("error", e.getMessage()));
        }
    }



    @PostMapping("/verify-reset-otp")
    public ResponseEntity<?> verifyResetOtp(@RequestBody VerifyEmailRequest request) {
        try {
            authService.verifyResetOtp(request.getVerificationToken(), request.getOtpCode());
            return ResponseEntity.ok(Map.of("message", "OTP verified successfully."));
        } catch (CustomException e) {
            return ResponseEntity.status(e.getStatus()).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        try {
            authService.resetPassword(request.getVerificationToken(), request);
            return ResponseEntity.ok(Map.of("message", "Password successfully reset."));
        } catch (CustomException e) {
            return ResponseEntity.status(e.getStatus()).body(Map.of("error", e.getMessage()));
        }
    }




    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody VerifyEmailRequest request) {
        try {
            authService.verifyOtpWithToken(request.getVerificationToken(), request.getOtpCode());
            return ResponseEntity.ok(Map.of("message", "OTP verified successfully."));
        } catch (CustomException e) {
            return ResponseEntity.status(e.getStatus()).body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<UserDTO> getCurrentUser() {
        String email = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        UserDTO userDTO = authService.getUserDetails(email);
        return ResponseEntity.ok(userDTO);
    }
}
