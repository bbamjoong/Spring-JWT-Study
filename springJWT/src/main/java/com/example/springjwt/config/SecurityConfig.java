package com.example.springjwt.config;

import com.example.springjwt.jwt.JWTFilter;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.jwt.LoginFilter;
import com.example.springjwt.util.CookieMethods;
import com.example.springjwt.util.RefreshEntityMethods;
import java.util.Collections;
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
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final CookieMethods cookieMethods;
    private final RefreshEntityMethods refreshEntityMethods;

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

        /**
         * cors 설정.
         * 보통 서버는 8080포트, 프론트엔드는 3000포트를 이용함.
         * 브라우저는 교차 출처 리소스 공유를 금지하기 때문에 데이터가 보이지 않음.
         * 따라서 별도의 cors 설정을 해주어 토큰을 허용해준다.
         */
        http
                .cors((cors) -> cors
                        .configurationSource(request -> {

                            CorsConfiguration configuration = new CorsConfiguration();

                            configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                            configuration.setAllowedMethods(Collections.singletonList("*"));
                            configuration.setAllowCredentials(true);
                            configuration.setAllowedHeaders(Collections.singletonList("*"));
                            configuration.setMaxAge(3600L);

                            configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                            return configuration;
                        }));

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
                        // access 토큰이 만료된 상태로 접근하기 때문에 로그인이 불가능한 상태이므로 permitAll
                        .requestMatchers("/reissue").permitAll()
                        .anyRequest().authenticated());

        /**
         * JWT Filter 등록
         * LoginFilter 이전에 작동 해야 함
         */
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        /**
         * UsernamePasswordAuthenticationFilter 클래스에 우리가 커스텀한 LoginFilter 추가
         * LoginFilter는 AuthenticationManager를 인자로 갖는다.
         *
         * Chapter10에서 LoginFilter클래스에 JWTUtil 인스턴스를 파라미터로 받도록 했다.
         * 따라서 의존성 주입을 해주도록 한다.
         */
        http
                .addFilterAt(
                        new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, cookieMethods,
                                refreshEntityMethods),
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