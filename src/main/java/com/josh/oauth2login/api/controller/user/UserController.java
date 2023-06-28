package com.josh.oauth2login.api.controller.user;

import com.josh.oauth2login.api.entity.user.MyUser;
import com.josh.oauth2login.api.service.UserService;
import com.josh.oauth2login.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    public ApiResponse getUser() {
//        log.info("Enter GetUser Controller");
        User principal = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        MyUser user = userService.getUser(principal.getUsername());

        return ApiResponse.success("user",user);
    }
}
