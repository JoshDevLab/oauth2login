package com.josh.oauth2login.domain.post.dto;

import com.josh.oauth2login.api.entity.user.Users;
import com.josh.oauth2login.domain.post.entity.Post;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PostDto {

    private Long postSeq;
    @NotNull
    private String title;
    @NotNull
    private String content;
    private LocalDateTime regDate;
    private LocalDateTime uptDate;
    private Long viewCount;
    @NotNull
    private Users user;

    public PostDto(Post post) {
        this.postSeq = post.getPostSeq();
        this.title = post.getTitle();
        this.content = post.getContent();
        this.regDate = post.getRegDate();
        this.viewCount = post.getViewCount();
    }

    public Post toEntity() {
        return Post.builder()
                .title(title)
                .content(content)
                .user(user)
                .build();
    }
}
