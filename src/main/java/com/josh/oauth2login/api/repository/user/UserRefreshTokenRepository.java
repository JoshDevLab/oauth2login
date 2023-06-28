package com.josh.oauth2login.api.repository.user;

import com.josh.oauth2login.api.entity.user.UserRefreshToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRefreshTokenRepository extends CrudRepository<UserRefreshToken, String> {
    UserRefreshToken findByUserId(String userId);
}

