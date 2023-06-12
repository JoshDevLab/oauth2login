package com.josh.oauth2login.oauth.service;

import com.josh.oauth2login.api.entity.user.Users;
import com.josh.oauth2login.api.repository.user.UserRepository;
import com.josh.oauth2login.oauth.entity.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = userRepository.findByUserId(username);
        if (user == null) {
            throw new UsernameNotFoundException("username 을 찾지 못했습니다.");
        }
        return UserPrincipal.create(user);
    }
}
