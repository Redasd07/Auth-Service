package com.auth.utils;

import com.auth.dto.*;
import com.auth.entity.*;
import com.auth.enums.Role;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;

@Component
public class DtoConverter {

    // Convert User entity to UserDTO
    public UserDTO toUserDTO(User user) {
        UserDTO userDTO = new UserDTO();
        BeanUtils.copyProperties(user, userDTO);
        userDTO.setRole(user.getRole().name());
        return userDTO;
    }

    // Convert UserDTO to User entity
    public User toUser(UserDTO userDTO) {
        User user = new User();
        BeanUtils.copyProperties(userDTO, user);
        user.setRole(Role.valueOf(userDTO.getRole().toUpperCase())); // Convert String to Enum
        return user;
    }

    // Convert User entity to RegisterRequest DTO
    public RegisterRequest toRegisterRequest(User user) {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setFirstName(user.getFirstName());
        registerRequest.setLastName(user.getLastName());
        registerRequest.setEmail(user.getEmail());
        registerRequest.setPhone(user.getPhone());
        return registerRequest;
    }

    // Convert RegisterRequest DTO to User entity
    public User toUser(RegisterRequest registerRequest) {
        User user = new User();
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setEmail(registerRequest.getEmail());
        user.setPhone(registerRequest.getPhone());
        return user;
    }

    // Convert User entity to ResetPasswordRequest DTO
    public ResetPasswordRequest toResetPasswordRequest(User user) {
        ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
        BeanUtils.copyProperties(user, resetPasswordRequest);
        return resetPasswordRequest;
    }

}
