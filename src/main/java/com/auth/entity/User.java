package com.auth.entity;

import com.auth.enums.Role;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Data
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "First name is required.")
    @Column(nullable = false)
    private String firstName;

    @NotBlank(message = "Last name is required.")
    @Column(nullable = false)
    private String lastName;

    @Email(message = "Please provide a valid email address.")
    @NotBlank(message = "Email is required.")
    @Column(nullable = false, unique = true)
    private String email;

    @Pattern(regexp = "^(06|05|07)[0-9]{8}$", message = "Invalid phone number format.")
    @NotBlank(message = "Phone number is required.")
    @Column(nullable = false, unique = true)
    private String phone;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Size(min = 8, message = "Password must be at least 8 characters long.")
    @NotBlank(message = "Password is required.")
    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private boolean emailVerified = false;

    private String otpCode;
    private LocalDateTime otpExpirationTime;

    @Column(nullable = true)
    private String otpContext; // Field to track the OTP context

    private String verificationToken;
    private LocalDateTime verificationTokenExpiration;

    private String resetToken; // Temporary token for password reset

    private LocalDateTime last2faVerification;
    private boolean force2faOnLogin = true;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    public void resetOtp() {
        this.otpCode = null;
        this.otpExpirationTime = null;
        this.otpContext = null; // Clear the context as well
    }
}
