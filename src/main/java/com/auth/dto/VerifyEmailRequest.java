package com.auth.dto;

import lombok.Data;

@Data
public class VerifyEmailRequest {
    private String verificationToken;
    private String otpCode;
}
