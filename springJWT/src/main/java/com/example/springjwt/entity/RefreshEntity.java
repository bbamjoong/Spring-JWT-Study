package com.example.springjwt.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

@Entity
@Data
public class RefreshEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username; // 하나의 유저가 여러 개의 토큰을 가질 수 있으므로 unique 옵션은 부여하지 않는다.
    private String refresh;
    private String expiration;
}
