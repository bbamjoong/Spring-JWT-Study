package com.example.springjwt.service;

import com.example.springjwt.dto.JoinDto;
import com.example.springjwt.entity.UserEntity;
import com.example.springjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDto joinDto) {

        String username = joinDto.getUsername();
        String password = joinDto.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) {
            return;
        }

        UserEntity data = new UserEntity();

        data.setUsername(username);
        // SecurityConfig 클래스에서 Bean으로 주입한 bCryptPasswordEncoder를 이용.
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }
}