package com.auth.service;

import com.auth.dto.*;
import com.auth.entity.User;
import com.auth.enums.Role;
import com.auth.repository.UserRepository;
import com.auth.security.jwt.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
    private final EmailService emailService;

    @Autowired
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       JwtTokenUtil jwtTokenUtil, EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenUtil = jwtTokenUtil;
        this.emailService = emailService;
    }

    /**
     * Inscription d'un nouvel utilisateur.
     */
    public void register(RegisterRequest request) {
        // Vérification si l'email est déjà utilisé
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("L'email est déjà utilisé.");
        }

        // Vérification de la correspondance des mots de passe
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new RuntimeException("Les mots de passe ne correspondent pas.");
        }

        // Création de l'utilisateur
        User user = new User();
        user.setNom(request.getNom());
        user.setPrenom(request.getPrenom());
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.CLIENT);
        user.setEmailVerified(false);

        // Génération et stockage d'un OTP pour la vérification de l'email
        String otp = generateOtp();
        user.setOtpCode(otp);
        user.setOtpExpirationTime(LocalDateTime.now().plusMinutes(15));

        userRepository.save(user);

        // Envoi de l'OTP par email
        emailService.sendOtpEmail(request.getEmail(), otp);
    }

    /**
     * Connexion de l'utilisateur et génération d'un token JWT.
     */
    public String login(LoginRequest request) {
        // Recherche de l'utilisateur par email
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé."));

        // Vérification du mot de passe
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Mot de passe incorrect.");
        }

        // Vérification que l'email a été vérifié
        if (!user.isEmailVerified()) {
            throw new RuntimeException("L'email n'a pas encore été vérifié.");
        }

        // Génération du token JWT
        return jwtTokenUtil.generateToken(user.getEmail(), user.getRole().name());
    }

    /**
     * Vérification de l'email à l'aide d'un OTP.
     */
    public void verifyEmail(VerifyEmailRequest request) {
        // Recherche de l'utilisateur par email
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé."));

        // Vérification de l'OTP
        if (!user.getOtpCode().equals(request.getOtpCode())) {
            throw new RuntimeException("Code OTP invalide.");
        }

        // Vérification que l'OTP n'a pas expiré
        if (LocalDateTime.now().isAfter(user.getOtpExpirationTime())) {
            throw new RuntimeException("Code OTP expiré.");
        }

        // Validation de l'email
        user.setEmailVerified(true);
        user.setOtpCode(null); // On invalide l'OTP
        user.setOtpExpirationTime(null);
        userRepository.save(user);
    }

    /**
     * Réinitialisation du mot de passe : demande d'un lien de réinitialisation.
     */
    public void forgotPassword(String email) {
        // Recherche de l'utilisateur par email
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé."));

        // Génération d'un OTP pour la réinitialisation
        String otp = generateOtp();
        user.setOtpCode(otp);
        user.setOtpExpirationTime(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        // Envoi de l'OTP par email
        emailService.sendPasswordResetEmail(email, otp);
    }

    /**
     * Réinitialisation du mot de passe avec validation du token.
     */
    public void resetPassword(String token, ResetPasswordRequest request) {
        // Recherche de l'utilisateur par OTP
        User user = userRepository.findByOtpCode(token)
                .orElseThrow(() -> new RuntimeException("Token invalide ou expiré."));

        // Vérification des mots de passe
        if (!request.getNewPassword().equals(request.getConfirmNewPassword())) {
            throw new RuntimeException("Les mots de passe ne correspondent pas.");
        }

        // Mise à jour du mot de passe
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setOtpCode(null); // On invalide le token
        user.setOtpExpirationTime(null);
        userRepository.save(user);
    }

    /**
     * Génération d'un OTP à 4 chiffres.
     */
    private String generateOtp() {
        return String.format("%04d", (int) (Math.random() * 10000));
    }
}
