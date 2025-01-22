package com.auth;

import com.auth.entity.User;
import com.auth.enums.Role;
import com.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    private User testUser;

    @BeforeEach
    void setUp() {
        // Create a test user
        testUser = new User();
        testUser.setFirstName("John");
        testUser.setLastName("Doe");
        testUser.setEmail("johndoe@example.com");
        testUser.setPhone("1234567890");
        testUser.setPassword("password123");
        testUser.setRole(Role.CLIENT);
        testUser.setEmailVerified(true);

        // Save test user to the database
        userRepository.save(testUser);
    }

    @Test
    void testFindByEmailSuccess() {
        // Test finding the user by email
        Optional<User> userOptional = userRepository.findByEmail("johndoe@example.com");

        assertTrue(userOptional.isPresent());
        assertEquals("John", userOptional.get().getFirstName());
        assertEquals("Doe", userOptional.get().getLastName());
    }

    @Test
    void testFindByEmailNotFound() {
        // Test finding a user by a non-existent email
        Optional<User> userOptional = userRepository.findByEmail("nonexistent@example.com");

        assertFalse(userOptional.isPresent());
    }

    @Test
    void testFindByPhoneSuccess() {
        // Test finding the user by phone number
        Optional<User> userOptional = userRepository.findByPhone("1234567890");

        assertTrue(userOptional.isPresent());
        assertEquals("johndoe@example.com", userOptional.get().getEmail());
    }

    @Test
    void testFindByPhoneNotFound() {
        // Test finding a user by a non-existent phone number
        Optional<User> userOptional = userRepository.findByPhone("0987654321");

        assertFalse(userOptional.isPresent());
    }

    @Test
    void testFindByVerificationTokenSuccess() {
        // Assign a verification token and save
        String verificationToken = "mockVerificationToken";
        testUser.setVerificationToken(verificationToken);
        userRepository.save(testUser);

        // Test finding the user by verification token
        Optional<User> userOptional = userRepository.findByVerificationToken(verificationToken);

        assertTrue(userOptional.isPresent());
        assertEquals("johndoe@example.com", userOptional.get().getEmail());
    }

    @Test
    void testFindByVerificationTokenNotFound() {
        // Test finding a user by a non-existent verification token
        Optional<User> userOptional = userRepository.findByVerificationToken("nonexistentToken");

        assertFalse(userOptional.isPresent());
    }
}
