package com.mini.anuualwork.config;

import com.mini.anuualwork.component.security.JwtAccessDeniedHandler;
import com.mini.anuualwork.component.security.JwtAuthenticationEntryPoint;
import com.mini.anuualwork.component.security.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /* Security 필터 체인 생성: antMatchers 설정은 여기서 진행 */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf().disable() // csrf 기능 비활성화
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용 X : StateLess 설정
                .and()
                .authorizeHttpRequests()
                .antMatchers("/api/admin/**").hasRole("ADMIN")
                .antMatchers("/api/user/**").hasAnyRole("USER", "ADMIN")
                .antMatchers(HttpMethod.GET, "/api/schedule/**").permitAll()
                .antMatchers("/api/login", "/api/logout", "/api/signup").permitAll()
                .antMatchers("/favicon.ico").permitAll()
                .antMatchers("/static/js/**", "/static/image/**", "/static/css/**", "/static/scss/**").permitAll()
                .anyRequest().authenticated() // 위에 지정한 antMatchers 이외에는 모두 인증 받아야 한다.
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));

        return httpSecurity.build();
    }
}
