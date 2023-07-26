package com.mini.anuualwork.component.security.filter;

import com.mini.anuualwork.component.security.TokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER = "Bearer ";
    public static final int ACTUAL_TOKEN_START_INDEX = 7;
    private final TokenProvider tokenProvider;

    /* 실제 필터링 동작 로직: Security Context에 저장 */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        String token = resolveToken(request);
        String requestURI = request.getRequestURI();

        if (StringUtils.hasText(token) && tokenProvider.validateToken(token)) {
            Authentication authentication = tokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("Security Context에 Authentication 정보가 정상적으로 저장되었습니다.");
        } else {
            log.info("유효한 토큰이 존재하지 않습니다. URI: {}", requestURI);
        }

        chain.doFilter(request, response);
    }

    /* HttpServletRequest 헤더에서 토큰 정보를 추출 (헤더의 토큰에서 Bearer 부분 떼고 실제 토큰 부분만 추출) */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER)) {
            return bearerToken.substring(ACTUAL_TOKEN_START_INDEX);
        }

        return null;
    }
}
