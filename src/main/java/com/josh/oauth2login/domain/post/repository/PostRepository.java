package com.josh.oauth2login.domain.post.repository;

import com.josh.oauth2login.domain.post.dto.PostDto;
import com.josh.oauth2login.domain.post.entity.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PostRepository extends JpaRepository<Post, Long> {
}
