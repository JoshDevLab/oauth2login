package com.josh.oauth2login.api.repository.user;

import com.josh.oauth2login.api.entity.user.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<Users, Long> {
    Users findByUserId(String userId);
}

