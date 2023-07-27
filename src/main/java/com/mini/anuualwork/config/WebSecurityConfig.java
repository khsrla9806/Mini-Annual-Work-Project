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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

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

        String[] permitAllEndPoints = {
                "/api/login", "/api/logout", "/api/signup", "/favicon.ico",
                "/static/js/**", "/static/image/**", "/static/css/**", "/static/scss/**"
        };

        httpSecurity
                .cors().configurationSource(this.configurationSource()) // Security Cors 설정
                .and()
                .csrf().disable() // csrf 기능 비활성화: POSTMAN 사용을 위해서
                .formLogin().disable() // Form Login 기능 제거 -> UsernamePasswordAuthenticationFilter 비활성화
                .httpBasic().disable() // Security 기본 로그인 페이지 뜨지 않도록 비활성화
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용 X : StateLess 설정 => JSessionId 사라짐
                .and()
                .authorizeHttpRequests()
                .antMatchers("/api/admin/**").hasRole("ADMIN")
                .antMatchers("/api/user/**").hasAnyRole("USER", "ADMIN")
                .antMatchers(HttpMethod.GET, "/api/schedule/**").permitAll()
                .antMatchers(permitAllEndPoints).permitAll()
                .anyRequest().authenticated() // 위에 지정한 antMatchers 이외에는 모두 인증 받아야 한다.
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));

        return httpSecurity.build();
    }

    private CorsConfigurationSource configurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*"); // 모든 Http Method 요청 허용
        configuration.addAllowedOriginPattern("*"); // TODO: Front-End IP만 허용 (지금은 모든 IP 접근 허용)
        configuration.setAllowCredentials(true); // 클라이언트에서 모든 쿠키 요청을 허용
        configuration.addExposedHeader("Authorization"); // 'Authorization' 헤더를 허용 (JWT)

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // /** 경로에 위에서 설정한 모든 Cors 설정을 적용

        return source;
    }
}
