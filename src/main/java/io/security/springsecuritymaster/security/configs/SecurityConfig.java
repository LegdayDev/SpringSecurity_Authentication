package io.security.springsecuritymaster.security.configs;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity // 스프링 시큐리티 활성화
@RequiredArgsConstructor
@Configuration // 스프링 Bean 등록
public class SecurityConfig {

    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.
                authorizeHttpRequests(auth -> auth // 요청에 대한 인가 설정
                        .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll() // 정적자원은 모두 허용
                        .requestMatchers("/", "/signup").permitAll() // 루트페이지는 허용
                        .anyRequest().authenticated() // 그 외 페이지 인증받아야 접속
                )
                .formLogin(form -> form.loginPage("/login").permitAll()) // formLogin 방식으로 /login 페이지로 연결 후 인증없이 모두 허용
                .authenticationProvider(authenticationProvider);

        return http.build();
    }
}