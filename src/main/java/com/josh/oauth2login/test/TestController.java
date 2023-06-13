package com.josh.oauth2login.test;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/test")
public class TestController {

    @PostMapping
    public ResponseEntity<User> test(@AuthenticationPrincipal User user) {
//        log.info("user info =====> {}", user);
        return ResponseEntity.ok(user);
    }
}
