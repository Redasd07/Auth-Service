package com.auth.entity;

import com.auth.enums.Role;
import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String nom;
    private String prenom;

    @Column(nullable = false, unique = true)
    private String email;

    private String phone;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    private String password;

    private boolean emailVerified = false;

    private String otpCode;

    private LocalDateTime otpExpirationTime;

    private LocalDateTime last2faVerification; // Date de la dernière vérification 2FA

    private boolean force2faOnLogin = true; // Indique si la 2FA est obligatoire pour la première connexion
}
