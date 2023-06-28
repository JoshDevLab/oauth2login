package com.josh.oauth2login.api.entity.user;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;


@Getter
@Setter
@NoArgsConstructor
@RedisHash(value = "refreshToken", timeToLive = 60)
public class UserRefreshToken {
    @Id
    private String refreshToken;

    @Indexed
    private String userId;

    public UserRefreshToken(final String userId, final String refreshToken) {
        this.userId = userId;
        this.refreshToken = refreshToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getUserId() {
        return userId;
    }
}

