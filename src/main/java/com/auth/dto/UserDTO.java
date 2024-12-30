package com.auth.dto;

import lombok.Data;

@Data
public class UserDTO {
    private Long id;
    private String nom;
    private String prenom;
    private String email;
    private String phone;
    private String role; // Représente le rôle (CLIENT ou ADMIN) sous forme de String
    private boolean emailVerified;
}
