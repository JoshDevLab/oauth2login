package com.josh.oauth2login.api.repository.user;

import com.josh.oauth2login.api.entity.user.MyUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<MyUser, Long> {
    MyUser findByUserId(String userId);
}

