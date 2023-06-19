package com.josh.oauth2login.oauth.filter;

import com.josh.oauth2login.oauth.token.AuthToken;
import com.josh.oauth2login.oauth.token.AuthTokenProvider;
import com.josh.oauth2login.utils.CookieUtil;
import com.josh.oauth2login.utils.HeaderUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

import static com.josh.oauth2login.oauth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository.REFRESH_TOKEN;

@Slf4j
@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final AuthTokenProvider tokenProvider;
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String requestURI = request.getRequestURI(); // 요청 URI
        log.info("requestURI {}", requestURI);
        String tokenStr = HeaderUtil.getAccessToken(request);
        log.info("tokenStr ====> {}", tokenStr);
        AuthToken token = tokenProvider.convertAuthToken(tokenStr);

        if (requestURI.equals("/api/v1/auth/refresh")) { // refresh token 발급을 위해 넘어오면 넘김
            log.info("requestURI.equals(\"/api/v1/auth/refresh\")");
            filterChain.doFilter(request, response);
//            return;
        }

        if (token.validate()) {
            log.info("token.validate() pass");
            Authentication authentication = tokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }
}
