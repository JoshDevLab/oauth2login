package com.josh.oauth2login.oauth.service;

import com.josh.oauth2login.api.entity.user.MyUser;
import com.josh.oauth2login.api.repository.user.UserRepository;
import com.josh.oauth2login.oauth.entity.ProviderType;
import com.josh.oauth2login.oauth.entity.RoleType;
import com.josh.oauth2login.oauth.entity.UserPrincipal;
import com.josh.oauth2login.oauth.exception.OAuthProviderMissMatchException;
import com.josh.oauth2login.oauth.info.OAuth2UserInfo;
import com.josh.oauth2login.oauth.info.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User user = super.loadUser(userRequest);

        return this.process(userRequest, user);
    }

    private OAuth2User process(OAuth2UserRequest userRequest, OAuth2User user) {

        //ProviderType 가져오기(GOOGLE, FACEBOOK, NAVER, KAKAO)
        ProviderType providerType = ProviderType.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase());

        //ProviderType 에 따른 유저정보 객체로 가져오기
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, user.getAttributes());

//        log.info("userInfo.getId() ===========> {}", userInfo.getId());

        MyUser savedUser = userRepository.findByUserId(userInfo.getId());

        if (savedUser != null) {
            if (providerType != savedUser.getProviderType()) { //저장된 유저가 ProviderType 이 다르게 접속이 온경우
                throw new OAuthProviderMissMatchException(
                        "Looks like you're signed up with " + providerType +
                        " account. Please use your " + savedUser.getProviderType() + " account to login."
                );
            }
            updateUser(savedUser, userInfo);
        } else {
            savedUser = createUser(userInfo, providerType);
        }

        return UserPrincipal.create(savedUser, user.getAttributes());
    }

    private MyUser createUser(OAuth2UserInfo userInfo, ProviderType providerType) {
        LocalDateTime now = LocalDateTime.now();
        MyUser user = new MyUser(
                userInfo.getId(),
                userInfo.getName(),
                userInfo.getEmail(),
                "Y",
                userInfo.getImageUrl(),
                providerType,
                RoleType.USER,
                now,
                now
        );

        return userRepository.saveAndFlush(user);
    }

    private MyUser updateUser(MyUser user, OAuth2UserInfo userInfo) {

        if (userInfo.getName() != null && !user.getUsername().equals(userInfo.getName())) {
            user.setUsername(userInfo.getName());
        }

        if (userInfo.getImageUrl() != null && !user.getProfileImageUrl().equals(userInfo.getImageUrl())) {
            user.setProfileImageUrl(userInfo.getImageUrl());
        }

        return user;
    }
}
