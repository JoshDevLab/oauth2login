package com.josh.oauth2login.oauth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static com.josh.oauth2login.common.JwtErrorCode.EXPIRED_TOKEN;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtExceptionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (JwtException e) {
//            log.info("e.getMessage() {}", e.getMessage());
            if (!(request.getRequestURI().equals("/api/v1/auth/refresh"))) {
                setErrorResponse(HttpStatus.UNAUTHORIZED, response, e);
            }
        }
    }

    private void setErrorResponse(HttpStatus status, HttpServletResponse response, Throwable ex) throws IOException {
//        log.info("ex.getClass() {}",ex.getClass());
        response.setStatus(status.value());
        response.setContentType("application/json; charset=UTF-8");

        final ObjectMapper objectMapper = new ObjectMapper();
        final Map<String, String> body = new HashMap<>();

        if (ex.getMessage().equals(EXPIRED_TOKEN)) {
            body.put("message", "Expired JWT token.");
        }

        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
