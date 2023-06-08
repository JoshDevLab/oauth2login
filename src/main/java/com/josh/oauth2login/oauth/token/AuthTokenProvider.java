package com.josh.oauth2login.oauth.token;

import com.josh.oauth2login.oauth.exception.TokenValidFailedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
public class AuthTokenProvider {

    private final Key key;
    private static final String AUTHORITIES_KEY = "role";

    public AuthTokenProvider(String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public AuthToken createAuthToken(String id, Date expiry) {
        return new AuthToken(id, expiry, key);
    }

    public AuthToken createAuthToken(String id, String role, Date expiry) {
        return new AuthToken(id, role, expiry, key);
    }

    public AuthToken convertAuthToken(String token) {
        return new AuthToken(token, key);
    }

    public Authentication getAuthentication(AuthToken authToken) {

        // AuthToken이 유효한지 확인합니다.
        if (authToken.validate()) {

            // 토큰에서 클레임(claims)을 가져옵니다.
            Claims claims = authToken.getTokenClaims();

            // 권한(authorities) 정보를 생성합니다.
            Collection<? extends GrantedAuthority> authorities = Arrays.stream(new String[]{claims.get(AUTHORITIES_KEY).toString()})
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            // 디버그 로그로 클레임의 주체(subject)를 출력합니다.
            log.debug("claims subject := [{}]", claims.getSubject());

            // 주체(subject)와 권한(authorities) 정보를 사용하여 User 객체를 생성합니다.
            // 비밀번호는 빈 문자열("")로 설정합니다.
            User principal = new User(claims.getSubject(), "", authorities);

            // UsernamePasswordAuthenticationToken을 생성하여 인증(Authentication) 객체를 반환합니다.
            // principal은 주체를 나타내는 User 객체입니다.
            // authToken은 사용된 인증 토큰을 나타내는 객체입니다.
            // authorities는 인증 주체(principal)의 권한 정보를 나타내는 컬렉션입니다.
            return new UsernamePasswordAuthenticationToken(principal, authToken, authorities);
        } else {
            throw new TokenValidFailedException();
        }
    }
}
