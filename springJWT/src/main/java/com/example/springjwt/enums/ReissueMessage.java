package com.example.springjwt.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ReissueMessage {
    REFRESH_NULL("refresh token null"),
    REFRESH_EXPIRED("refresh token expired"),
    REFRESH_INVALID("invalid refresh token");

    private final String message;
}
