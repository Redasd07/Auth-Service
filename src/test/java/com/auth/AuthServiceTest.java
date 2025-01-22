package com.auth;

import com.auth.dto.*;
import com.auth.entity.User;
import com.auth.enums.Role;
import com.auth.exception.CustomException;
import com.auth.repository.UserRepository;
import com.auth.security.jwt.JwtTokenUtil;
import com.auth.service.AuthService;
import com.auth.service.EmailService;
import com.auth.utils.DtoConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AuthServiceTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenUtil jwtTokenUtil;

    @Mock
    private EmailService emailService;

    @Mock
    private DtoConverter dtoConverter;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testRegisterSuccess() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("password123");
        registerRequest.setConfirmPassword("password123");
        registerRequest.setPhone("1234567890");

        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByPhone(anyString())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");

        User savedUser = new User();
        savedUser.setEmail("test@example.com");
        savedUser.setPassword("encodedPassword");
        savedUser.setRole(Role.CLIENT);
        savedUser.setPhone("1234567890");
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        User result = authService.register(registerRequest);

        assertNotNull(result);
        assertEquals("test@example.com", result.getEmail());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void testLoginWithDetailsSuccess() {
        // Mock user
        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("encodedPassword");
        user.setRole(Role.CLIENT);
        user.setEmailVerified(true);
        user.setForce2faOnLogin(false); // Ensure 2FA is disabled for this test

        // Mock behavior
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(jwtTokenUtil.generateToken(anyString(), anyString())).thenReturn("mockJwtToken");
        when(dtoConverter.toUserDTO(any(User.class))).thenReturn(new UserDTO(user.getEmail()));

        // Execute
        Map<String, Object> response = authService.loginWithDetails(new LoginRequest());

        // Verify
        assertNotNull(response);
        assertEquals("mockJwtToken", response.get("token"));
        verify(jwtTokenUtil, times(1)).generateToken(eq("test@example.com"), eq("CLIENT"));
    }


    @Test
    void testForgotPasswordEmailVerified() {
        User user = new User();
        user.setEmail("test@example.com");
        user.setEmailVerified(true);

        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));
        when(passwordEncoder.encode(anyString())).thenReturn("encodedOtp");

        String token = authService.forgotPassword("test@example.com");

        assertNotNull(token);
        verify(emailService, times(1)).sendPasswordResetEmail(eq("test@example.com"), anyString());
    }
}
