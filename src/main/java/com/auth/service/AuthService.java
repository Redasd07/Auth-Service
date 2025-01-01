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
            throw new CustomException("Email is already in use", HttpStatus.CONFLICT);
        }

        if (userRepository.findByPhone(request.getPhone()).isPresent()) {
            throw new CustomException("Phone number is already in use", HttpStatus.CONFLICT);
        }

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new CustomException("Passwords do not match", HttpStatus.BAD_REQUEST);
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
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));

        if (!user.getOtpCode().equals(request.getOtpCode())) {
            throw new CustomException("Invalid OTP code", HttpStatus.BAD_REQUEST);
        }

        if (LocalDateTime.now().isAfter(user.getOtpExpirationTime())) {
            throw new CustomException("OTP code expired", HttpStatus.BAD_REQUEST);
        }

        user.setEmailVerified(true);
        user.setOtpCode(null);
        user.setOtpExpirationTime(null);
        userRepository.save(user);
    }

    public Map<String, Object> loginWithDetails(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new CustomException("Incorrect password", HttpStatus.UNAUTHORIZED);
        }

        if (!user.isEmailVerified()) {
            throw new CustomException("Email is not verified", HttpStatus.FORBIDDEN);
        }

        boolean is2faRequired = user.isForce2faOnLogin() ||
                user.getLast2faVerification() == null ||
                user.getLast2faVerification().isBefore(LocalDateTime.now().minusDays(3));

        if (is2faRequired) {
            generateAndSendOtp(user.getEmail());
            user.setForce2faOnLogin(false);
            userRepository.save(user);
            throw new CustomException("OTP required", HttpStatus.ACCEPTED);
        }

        String token = jwtTokenUtil.generateToken(user.getEmail(), user.getRole().name());

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("user", dtoConverter.toUserDTO(user));
        return response;
    }

    public void generateAndSendOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));

        String otp = generateOtp();
        user.setOtpCode(otp);
        user.setOtpExpirationTime(LocalDateTime.now().plusMinutes(5));
        userRepository.save(user);

        emailService.sendOtpEmail(email, otp);
    }

    public void verifyOtp(String email, String otpCode) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));

        if (!user.getOtpCode().equals(otpCode)) {
            throw new CustomException("Invalid OTP code", HttpStatus.BAD_REQUEST);
        }

        if (LocalDateTime.now().isAfter(user.getOtpExpirationTime())) {
            throw new CustomException("OTP code expired", HttpStatus.BAD_REQUEST);
        }

        user.setLast2faVerification(LocalDateTime.now());
        user.setOtpCode(null);
        user.setOtpExpirationTime(null);
        userRepository.save(user);
    }

    public UserDTO getUserDetails(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));
        return dtoConverter.toUserDTO(user);
    }

    public void forgotPassword(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("User not found", HttpStatus.NOT_FOUND));

        String otp = generateOtp();
        user.setOtpCode(otp);
        user.setOtpExpirationTime(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        emailService.sendPasswordResetEmail(email, otp);
    }

    public void resetPassword(String token, ResetPasswordRequest request) {
        User user = userRepository.findByOtpCode(token)
                .orElseThrow(() -> new CustomException("Invalid or expired token", HttpStatus.BAD_REQUEST));

        if (!request.getNewPassword().equals(request.getConfirmNewPassword())) {
            throw new CustomException("Passwords do not match", HttpStatus.BAD_REQUEST);
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setOtpCode(null);
        user.setOtpExpirationTime(null);
        userRepository.save(user);
    }

    private String generateOtp() {
        return String.format("%04d", (int) (Math.random() * 10000));
    }
}