package com.auth.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.Map;

@Getter
public class CustomException extends RuntimeException {
    private final HttpStatus status;
    private final Map<String, Object> additionalData;

    public CustomException(String message, HttpStatus status) {
        super(message);
        this.status = status;
        this.additionalData = null;
    }

    public CustomException(String message, HttpStatus status, Map<String, Object> additionalData) {
        super(message);
        this.status = status;
        this.additionalData = additionalData;
    }
}
