package com.josh.oauth2login.api.service;

import com.josh.oauth2login.api.entity.user.MyUser;
import com.josh.oauth2login.api.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public MyUser getUser(String userId) {
        return userRepository.findByUserId(userId);
    }
}