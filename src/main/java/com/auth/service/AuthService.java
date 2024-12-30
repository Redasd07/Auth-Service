package com.auth.service;

import com.auth.dto.*;
import com.auth.entity.User;
import com.auth.enums.Role;
import com.auth.repository.UserRepository;
import com.auth.security.jwt.JwtTokenUtil;
import com.auth.utils.DtoConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
    private final EmailService emailService;
    private final DtoConverter dtoConverter;

    @Autowired
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       JwtTokenUtil jwtTokenUtil, EmailService emailService,
                       DtoConverter dtoConverter) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenUtil = jwtTokenUtil;
        this.emailService = emailService;
        this.dtoConverter = dtoConverter;
    }

    public User register(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("L'email est déjà utilisé.");
        }

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new RuntimeException("Les mots de passe ne correspondent pas.");
        }

        User user = new User();
        user.setNom(request.getNom());
        user.setPrenom(request.getPrenom());
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.CLIENT);
        user.setEmailVerified(false);

        String otp = generateOtp();
        user.setOtpCode(otp);
        user.setOtpExpirationTime(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        emailService.sendOtpEmail(request.getEmail(), otp);
        return user;
    }

    public void verifyEmail(VerifyEmailRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé."));

        if (!user.getOtpCode().equals(request.getOtpCode())) {
            throw new RuntimeException("Code OTP invalide.");
        }

        if (LocalDateTime.now().isAfter(user.getOtpExpirationTime())) {
            throw new RuntimeException("Code OTP expiré.");
        }

        user.setEmailVerified(true);
        user.setOtpCode(null);
        user.setOtpExpirationTime(null);
        userRepository.save(user);
    }

    public Map<String, Object> loginWithDetails(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé."));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Mot de passe incorrect.");
        }

        if (!user.isEmailVerified()) {
            throw new RuntimeException("L'email n'a pas encore été vérifié.");
        }

        boolean is2faRequired = user.isForce2faOnLogin() ||
                user.getLast2faVerification() == null ||
                user.getLast2faVerification().isBefore(LocalDateTime.now().minusDays(3));

        if (is2faRequired) {
            generateAndSendOtp(user.getEmail());
            user.setForce2faOnLogin(false);
            userRepository.save(user);
            throw new RuntimeException("OTP required.");
        }

        String token = jwtTokenUtil.generateToken(user.getEmail(), user.getRole().name());

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("user", dtoConverter.toUserDTO(user));
        return response;
    }

    public void generateAndSendOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé."));

        // Génération du nouvel OTP
        String otp = generateOtp();
        user.setOtpCode(otp);
        user.setOtpExpirationTime(LocalDateTime.now().plusMinutes(5));
        userRepository.save(user);

        // Envoi de l'OTP par email
        emailService.sendOtpEmail(email, otp);
    }


    public void verifyOtp(String email, String otpCode) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé."));

        if (!user.getOtpCode().equals(otpCode)) {
            throw new RuntimeException("Code OTP invalide.");
        }

        if (LocalDateTime.now().isAfter(user.getOtpExpirationTime())) {
            throw new RuntimeException("Code OTP expiré.");
        }

        user.setLast2faVerification(LocalDateTime.now());
        user.setOtpCode(null); // Invalider l'OTP après utilisation
        user.setOtpExpirationTime(null);
        userRepository.save(user);
    }

    public UserDTO getUserDetails(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé."));
        return dtoConverter.toUserDTO(user);
    }

    public void forgotPassword(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé."));

        String otp = generateOtp();
        user.setOtpCode(otp);
        user.setOtpExpirationTime(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        emailService.sendPasswordResetEmail(email, otp);
    }

    public void resetPassword(String token, ResetPasswordRequest request) {
        User user = userRepository.findByOtpCode(token)
                .orElseThrow(() -> new RuntimeException("Token invalide ou expiré."));

        if (!request.getNewPassword().equals(request.getConfirmNewPassword())) {
            throw new RuntimeException("Les mots de passe ne correspondent pas.");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setOtpCode(null);
        user.setOtpExpirationTime(null);
        userRepository.save(user);
    }

    private String generateOtp() {
        return String.format("%04d", (int) (Math.random() * 1000000));
    }
}
