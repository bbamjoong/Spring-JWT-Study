package com.example.springjwt.dto;

import com.example.springjwt.entity.UserEntity;
import java.util.ArrayList;
import java.util.Collection;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@AllArgsConstructor
public class CustomUserDetails implements UserDetails {
    
    private final UserEntity userEntity;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { //권한을 반환하는 메소드

        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(userEntity::getRole);

        return collection;
    }

    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }


    @Override
    public boolean isAccountNonExpired() { // 사용자의 계정이 만료되었는지?
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { // 사용자의 계정이 잠겨있는지?
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { // 자격증명이 만료되었는지?
        return true;
    }

    @Override
    public boolean isEnabled() { // 사용가능 여부
        return true;
    }
}