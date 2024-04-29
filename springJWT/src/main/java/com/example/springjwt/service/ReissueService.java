package com.example.springjwt.service;

import static com.example.springjwt.enums.ReissueMessage.REFRESH_EXPIRED;
import static com.example.springjwt.enums.ReissueMessage.REFRESH_INVALID;
import static com.example.springjwt.enums.ReissueMessage.REFRESH_NULL;

import com.example.springjwt.jwt.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ReissueService {

    private final JWTUtil jwtUtil;

    public String findRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        return Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals("refresh"))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);
    }

    public String reissueToken(HttpServletRequest request) {
        String refreshToken = findRefreshToken(request);

        // 토큰 존재 여부 확인
        if (refreshToken == null) {
            return REFRESH_NULL.getMessage();
        }

        // 토큰 만료 여부 확인
        try {
            jwtUtil.isExpired(refreshToken);
        } catch (ExpiredJwtException e) {
            return REFRESH_EXPIRED.getMessage();
        }

        // 토큰 카테고리 확인
        String category = jwtUtil.getCategory(refreshToken);
        if (!category.equals("refresh")) {
            return REFRESH_INVALID.getMessage();
        }

        return refreshToken;
    }

    public String getNewAccess(String refresh) {
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        return jwtUtil.createJwt("access", username, role, 600_000L);
    }
}
