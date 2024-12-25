package com.auth.dto;

import lombok.Data;

public class VerifyEmailRequest {
    private String email;
    private String otpCode;

    public String getOtpCode() {
        return otpCode;
    }

    public void setOtpCode(String otpCode) {
        this.otpCode = otpCode;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public VerifyEmailRequest() {

    }
    public VerifyEmailRequest(String email, String otpCode) {
        this.email = email;
        this.otpCode = otpCode;
    }
}
