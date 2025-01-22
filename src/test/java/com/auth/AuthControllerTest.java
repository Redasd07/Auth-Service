package com.auth;

import com.auth.controller.AuthController;
import com.auth.dto.LoginRequest;
import com.auth.dto.RegisterRequest;
import com.auth.dto.UserDTO;
import com.auth.entity.User;
import com.auth.service.AuthService;
import com.auth.utils.DtoConverter;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @SpringMockBean
    private AuthService authService;

    @SpringMockBean
    private DtoConverter dtoConverter;

    @Test
    void testRegisterSuccess() throws Exception {
        // Mocking dependencies
        User mockUser = new User();
        mockUser.setEmail("testuser@example.com");
        mockUser.setRole(com.auth.enums.Role.USER);

        UserDTO mockUserDTO = new UserDTO(mockUser.getEmail());
        mockUserDTO.setRole(mockUser.getRole().name());

        Mockito.when(authService.register(any(RegisterRequest.class))).thenReturn(mockUser);
        Mockito.when(authService.generateEmailVerificationToken(eq("testuser@example.com")))
                .thenReturn("mockVerificationToken");
        Mockito.when(dtoConverter.toUserDTO(any(User.class))).thenReturn(mockUserDTO);

        // Test data
        String requestBody = """
                {
                    "email": "testuser@example.com",
                    "password": "password123"
                }
                """;

        // Execute test
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.email").value("testuser@example.com"))
                .andExpect(jsonPath("$.user.role").value("USER"))
                .andExpect(jsonPath("$.verificationToken").value("mockVerificationToken"));
    }

    @Test
    void testLoginSuccess() throws Exception {
        // Mocking login response
        Map<String, Object> mockResponse = Map.of("token", "mockJwtToken");

        Mockito.when(authService.loginWithDetails(any(LoginRequest.class))).thenReturn(mockResponse);

        // Test data
        String requestBody = """
                {
                    "email": "testuser@example.com",
                    "password": "password123"
                }
                """;

        // Execute test
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("mockJwtToken"));
    }

    @Test
    void testGetCurrentUser() throws Exception {
        // Mocking dependencies
        User mockUser = new User();
        mockUser.setEmail("testuser@example.com");
        mockUser.setRole(com.auth.enums.Role.USER);

        UserDTO mockUserDTO = new UserDTO(mockUser.getEmail());
        mockUserDTO.setRole(mockUser.getRole().name());

        Mockito.when(authService.getUserDetails(eq(mockUser.getEmail()))).thenReturn(mockUserDTO);

        // Execute test
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("testuser@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));
    }
}
