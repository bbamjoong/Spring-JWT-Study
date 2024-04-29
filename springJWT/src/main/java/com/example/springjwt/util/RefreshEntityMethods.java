package com.example.springjwt.util;

import com.example.springjwt.entity.RefreshEntity;
import com.example.springjwt.repository.RefreshRepository;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RefreshEntityMethods {
    private final RefreshRepository refreshRepository;

    // RefreshEntity 생성 및 저장
    public void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }
}
