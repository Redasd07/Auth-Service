package com.auth.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender emailSender;

    public EmailServiceImpl(JavaMailSender emailSender) {
        this.emailSender = emailSender;
    }

    @Override
    public void sendOtpEmail(String to, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Code de vérification de votre compte ScanMe");
        message.setText("Bonjour,\n\n" +
                "Merci de vous être inscrit sur ScanMe !\n\n" +
                "Pour finaliser votre inscription, veuillez utiliser le code suivant pour vérifier votre email :\n" +
                otp + "\n\n" +
                "Ce code est valable pendant 15 minutes.\n\n" +
                "Si vous n'avez pas initié cette demande, veuillez ignorer cet email.\n\n" +
                "Cordialement,\n" +
                "L'équipe ScanMe.");
        emailSender.send(message);
    }

    @Override
    public void sendPasswordResetEmail(String to, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Password Reset OTP for ScanMe");
        message.setText("Bonjour,\n\n" +
                "Nous avons reçu une demande de réinitialisation de votre mot de passe. Voici votre OTP :\n" +
                otp + "\n\n" +
                "Ce code est valable pendant 15 minutes.\n\n" +
                "Si vous n'avez pas demandé cette réinitialisation, veuillez ignorer cet email.\n\n" +
                "Cordialement,\n" +
                "L'équipe ScanMe.");
        emailSender.send(message);
    }


    @Override
    public void sendTwoFactorOtp(String to, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Code de vérification 2FA pour votre connexion ScanMe");
        message.setText("Bonjour,\n\n" +
                "Nous avons détecté une tentative de connexion à votre compte ScanMe. Pour sécuriser votre accès, veuillez entrer le code suivant :\n" +
                otp + "\n\n" +
                "Ce code est valable pendant 5 minutes.\n\n" +
                "Si vous n'êtes pas à l'origine de cette demande, veuillez immédiatement changer votre mot de passe et nous contacter.\n\n" +
                "Cordialement,\n" +
                "L'équipe ScanMe.");
        emailSender.send(message);
    }

    @Override
    public void sendResendOtpEmail(String to, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Votre nouveau code OTP pour ScanMe");
        message.setText("Bonjour,\n\n" +
                "Vous avez demandé un nouveau code OTP pour valider votre compte ou accéder à votre compte.\n\n" +
                "Voici votre nouveau code OTP : " + otp + "\n\n" +
                "Ce code est valable pendant 15 minutes.\n\n" +
                "Si vous n'avez pas initié cette demande, veuillez ignorer cet email.\n\n" +
                "Cordialement,\n" +
                "L'équipe ScanMe.");
        emailSender.send(message);
    }
}


