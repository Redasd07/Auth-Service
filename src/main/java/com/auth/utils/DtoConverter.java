package com.auth.utils;

import com.auth.dto.*;
import com.auth.entity.*;
import com.auth.enums.Role;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;

@Component
public class DtoConverter {

    public UserDTO toUserDTO(User user) {
        UserDTO userDTO = new UserDTO();
        BeanUtils.copyProperties(user, userDTO);
        userDTO.setRole(user.getRole().name());
        return userDTO;
    }

    public User toUser(UserDTO userDTO) {
        User user = new User();
        BeanUtils.copyProperties(userDTO, user);
        user.setRole(Role.valueOf(userDTO.getRole().toUpperCase())); // Convert String to Enum
        return user;
    }

    public RegisterRequest toRegisterRequest(User user) {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setNom(user.getNom());
        registerRequest.setPrenom(user.getPrenom());
        registerRequest.setEmail(user.getEmail());
        registerRequest.setPhone(user.getPhone());
        return registerRequest;
    }

    public User toUser(RegisterRequest registerRequest) {
        User user = new User();
        user.setNom(registerRequest.getNom());
        user.setPrenom(registerRequest.getPrenom());
        user.setEmail(registerRequest.getEmail());
        user.setPhone(registerRequest.getPhone());
        return user;
    }

    public ResetPasswordRequest toResetPasswordRequest(User user) {
        ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
        BeanUtils.copyProperties(user, resetPasswordRequest);
        return resetPasswordRequest;
    }

    public VerifyEmailRequest toVerifyEmailRequest(User user) {
        VerifyEmailRequest verifyEmailRequest = new VerifyEmailRequest();
        verifyEmailRequest.setEmail(user.getEmail());
        verifyEmailRequest.setOtpCode(user.getOtpCode());
        return verifyEmailRequest;
    }
}
