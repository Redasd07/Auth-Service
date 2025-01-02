package com.auth.service;

import com.auth.dto.*;
import com.auth.entity.User;
import com.auth.enums.Role;
import com.auth.exception.CustomException;
import com.auth.repository.UserRepository;
import com.auth.security.jwt.JwtTokenUtil;
import com.auth.utils.DtoConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
    private final EmailService emailService;
    private final DtoConverter dtoConverter;

    @Autowired
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       JwtTokenUtil jwtTokenUtil, EmailService emailService, DtoConverter dtoConverter) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenUtil = jwtTokenUtil;
        this.emailService = emailService;
        this.dtoConverter = dtoConverter;
    }

    public User register(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new CustomException("Email is already in use", HttpStatus.CONFLICT);
        }

        if (userRepository.findByPhone(request.getPhone()).isPresent()) {
            throw new CustomException("Phone number is already in use", HttpStatus.CONFLICT);
        }

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new CustomException("Passwords do not match", HttpStatus.BAD_REQUEST);
        }

        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.CLIENT);
        user.setEmailVerified(false);
        userRepository.save(user);

        return user;
    }

    public String generateEmailVerificationToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));

        String verificationToken = UUID.randomUUID().toString();
        user.setVerificationToken(verificationToken);

        generateAndSendOtp(user, 15, "EMAIL_VERIFICATION");
        return verificationToken;
    }

    public void verifyEmailWithToken(String verificationToken, String otpCode) {
        User user = getUserByToken(verificationToken);
        validateOtp(user, otpCode);

        user.setEmailVerified(true);
        user.setVerificationToken(null);
        userRepository.save(user);
    }

    public String forgotPassword(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));

        if (!user.isEmailVerified()) {
            // Si l'email n'est pas vérifié, renvoyer un OTP pour vérification de l'email
            String verificationToken = UUID.randomUUID().toString();
            user.setVerificationToken(verificationToken);

            generateAndSendOtp(user, 15, "EMAIL_VERIFICATION");

            userRepository.save(user);

            throw new CustomException(
                    "Email is not verified",
                    HttpStatus.FORBIDDEN,
                    Map.of("verificationToken", verificationToken, "message", "An OTP has been sent to your email for verification.")
            );
        }

        // Si l'email est vérifié, générer un OTP pour le reset password
        String verificationToken = UUID.randomUUID().toString();
        String otp = generateOtp();

        user.setVerificationToken(verificationToken);
        user.setOtpCode(otp);
        user.setOtpExpirationTime(LocalDateTime.now().plusMinutes(15));

        userRepository.save(user);

        emailService.sendPasswordResetEmail(user.getEmail(), otp);

        return verificationToken;
    }



    public void resetPassword(String verificationToken, ResetPasswordRequest request) {
        User user = getUserByToken(verificationToken);

        if (!request.getNewPassword().equals(request.getConfirmNewPassword())) {
            throw new CustomException("Passwords do not match", HttpStatus.BAD_REQUEST);
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setVerificationToken(null);
        userRepository.save(user);
    }

    public void resendEmailVerificationOtp(String verificationToken) {
        User user = getUserByToken(verificationToken);
        generateAndSendOtp(user, 15, "EMAIL_VERIFICATION");
    }


    public void resendTwoFactorOtp(String verificationToken) {
        User user = getUserByToken(verificationToken);
        generateAndSendOtp(user, 5, "2FA");
    }

    public Map<String, Object> loginWithDetails(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new CustomException("Incorrect password", HttpStatus.UNAUTHORIZED);
        }

        if (!user.isEmailVerified()) {
            generateAndSendOtp(user, 15, "EMAIL_VERIFICATION");
            throw new CustomException(
                    "Email is not verified",
                    HttpStatus.FORBIDDEN,
                    Map.of("message", "An OTP has been sent to your email for verification.")
            );
        }

        boolean is2faRequired = user.isForce2faOnLogin() ||
                user.getLast2faVerification() == null ||
                user.getLast2faVerification().isBefore(LocalDateTime.now().minusDays(3));

        if (is2faRequired) {
            generateAndSend2FAOtp(user.getEmail());
            user.setForce2faOnLogin(false);

            if (user.getVerificationToken() == null) {
                String verificationToken = UUID.randomUUID().toString();
                user.setVerificationToken(verificationToken);
            }

            userRepository.save(user);

            Map<String, Object> additionalData = Map.of("verificationToken", user.getVerificationToken());
            throw new CustomException("OTP required", HttpStatus.ACCEPTED, additionalData);
        }

        String token = jwtTokenUtil.generateToken(user.getEmail(), user.getRole().name());

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("user", dtoConverter.toUserDTO(user));
        return response;
    }

    public void verifyResetOtp(String verificationToken, String otpCode) {
        User user = getUserByToken(verificationToken);
        validateOtp(user, otpCode);
    }

    public void verifyOtpWithToken(String verificationToken, String otpCode) {
        User user = getUserByToken(verificationToken);
        validateOtp(user, otpCode);

        user.setLast2faVerification(LocalDateTime.now());
        user.setForce2faOnLogin(false);
        userRepository.save(user);
    }

    public UserDTO getUserDetails(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));
        return new UserDTO(user.getId(), user.getFirstName(), user.getLastName(), user.getEmail(), user.getPhone(), user.getRole().name(), user.isEmailVerified());
    }
    public void resendOtp(String verificationToken, String context) {
        User user = getUserByToken(verificationToken);

        switch (context) {
            case "EMAIL_VERIFICATION":
                generateAndSendOtp(user, 15, "EMAIL_VERIFICATION");
                break;
            case "RESET_PASSWORD":
                generateAndSendOtp(user, 15, "RESET_PASSWORD");
                break;
            case "2FA":
                generateAndSendOtp(user, 5, "2FA");
                break;
            default:
                throw new CustomException("Invalid context for OTP resend", HttpStatus.BAD_REQUEST);
        }
    }


    private void generateAndSendOtp(User user, int expirationMinutes, String context) {
        String otp = generateOtp();
        user.setOtpCode(otp);
        user.setOtpExpirationTime(LocalDateTime.now().plusMinutes(expirationMinutes));
        userRepository.save(user);

        switch (context) {
            case "2FA":
                emailService.sendTwoFactorOtp(user.getEmail(), otp);
                break;
            case "RESET_PASSWORD":
                emailService.sendPasswordResetEmail(user.getEmail(), otp);
                break;
            default:
                emailService.sendOtpEmail(user.getEmail(), otp);
                break;
        }
    }

    private void validateOtp(User user, String otpCode) {
        if (!user.getOtpCode().equals(otpCode)) {
            throw new CustomException("Invalid OTP code", HttpStatus.BAD_REQUEST);
        }

        if (LocalDateTime.now().isAfter(user.getOtpExpirationTime())) {
            throw new CustomException("OTP code expired", HttpStatus.BAD_REQUEST);
        }

        user.setOtpCode(null);
        user.setOtpExpirationTime(null);
        userRepository.save(user);
    }

    private User getUserByToken(String token) {
        return userRepository.findByVerificationToken(token)
                .orElseThrow(() -> new CustomException("Invalid or expired token", HttpStatus.BAD_REQUEST));
    }

    private void generateAndSend2FAOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));

        generateAndSendOtp(user, 5, "2FA");
    }
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));
    }


    private String generateOtp() {
        return String.format("%04d", (int) (Math.random() * 10000));
    }
}
