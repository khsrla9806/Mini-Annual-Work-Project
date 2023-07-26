package com.mini.anuualwork.config;

import com.mini.anuualwork.component.security.TokenProvider;
import com.mini.anuualwork.component.security.filter.JwtFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private final TokenProvider tokenProvider;

    /* Security의 UsernamePasswordAuthenticationFilter 전에 우리가 만든 JwtFilter를 추가 */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
    }
}
