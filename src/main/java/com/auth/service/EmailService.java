package com.auth.service;

public interface EmailService {
    void sendOtpEmail(String to, String otp);
    void sendPasswordResetEmail(String to, String resetToken);
}
