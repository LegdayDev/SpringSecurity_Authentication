package io.security.springsecuritymaster.security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity // 스프링 시큐리티 활성화
@Configuration // 스프링 Bean 등록
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.
                authorizeHttpRequests(auth -> auth // 요청에 대한 인가 설정
                        .requestMatchers("/").permitAll() // 루트페이지는 허용
                        .anyRequest().authenticated() // 그 외 페이지 인증받아야 접속
                )
                .formLogin(Customizer.withDefaults()) // form 로그인 방식으로 기본 구성으로 설정
        ;
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() { // 사용자 객체 생성
        // 유저네임이 user 이고 비밀번호는 인코딩되지 않은({noop}) 1111 이고 역할은 USER 로 생성한다.
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        // 메모리 내에 사용자 정보를 저장하고 관리하는 InMemoryUserDetailsManager 를 빈으로 등록하여 그 안에 위 user 객체를 생성자로 전달
        return new InMemoryUserDetailsManager(user);
    }
}