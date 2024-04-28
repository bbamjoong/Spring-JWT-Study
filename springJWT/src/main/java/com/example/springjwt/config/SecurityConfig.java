package com.example.springjwt.config;

import com.example.springjwt.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;

    // BCrypt Password Encoder 객체를 생성하여 반환하는 Bean 생성
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    // AuthenticationManager Bean 등록
    // Authenticationfiguration을 파라미터로 받기 때문에 SecurityConfig 클래스에서 의존성 주입을 해준다.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf disable
        /**
         * session 방식은 session이 고정적이기 때문에 csrf 공격을 방어해주어야 한다.
         * JWT는 session을 Stateless 상태로 관리하기 때문에 disable로 둔다.
         */
        http
                .csrf((auth) -> auth.disable());

        /**
         * JWT를 쓰므로 formLogin, httpBasic 인증 방식 또한 disable 해준다.
         */
        //From 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());
        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        /**
         * UsernamePasswordAuthenticationFilter 클래스에 우리가 커스텀한 LoginFilter 추가
         * LoginFilter는 AuthenticationManager를 인자로 갖는다.
         */
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration)),
                        UsernamePasswordAuthenticationFilter.class);

        /**
         * session을 stateless한 상태로 관리하기 위해 해당 설정을 해준다.
         */
        //세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}