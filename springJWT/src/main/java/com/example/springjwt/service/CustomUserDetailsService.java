package com.example.springjwt.service;

import com.example.springjwt.dto.CustomUserDetails;
import com.example.springjwt.entity.UserEntity;
import com.example.springjwt.repository.UserRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //DB에서 조회
        Optional<UserEntity> userData = userRepository.findByUsername(username);

        /**
         * 1. UserRepository가 DB에서 조회
         * 2. UserDetailsService에서 loadUserByUsername 메소드 실행
         * 3. User가 존재할 경우 UserDetails에서 검증
         */
        //UserDetails에 담아서 return하면 AutneticationManager가 검증 함
        return userData.map(CustomUserDetails::new).orElse(null);

    }
}
