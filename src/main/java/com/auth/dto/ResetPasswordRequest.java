package com.auth.dto;

import lombok.Data;

@Data
public class ResetPasswordRequest {
    private String verificationToken; // Remplace resetToken par verificationToken
    private String newPassword;
    private String confirmNewPassword;
}
