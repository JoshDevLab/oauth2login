package com.josh.oauth2login.domain.post.controller;

import com.josh.oauth2login.domain.post.dto.PostDto;
import com.josh.oauth2login.domain.post.entity.Post;
import com.josh.oauth2login.domain.post.service.PostService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/posts")
public class PostController {

    private final PostService postService;

    @PostMapping
    public ResponseEntity<Integer> registerPost(@RequestBody PostDto postDto, @AuthenticationPrincipal User user) {
        log.info("postDto {}", postDto);
        log.info("user {}", user);
        PostDto rePostDto = postService.registerBoard(postDto);
        if (rePostDto == null) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return ResponseEntity.ok(1);
    }

    @GetMapping
    public ResponseEntity<List<PostDto>> getPosts() {
        return ResponseEntity.ok(postService.getPosts());
    }
}
