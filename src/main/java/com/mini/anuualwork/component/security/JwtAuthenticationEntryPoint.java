package com.mini.anuualwork.component.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mini.anuualwork.core.ApiErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {

        log.info("인가 받지 않은 요청입니다.");

        // 인가 받지 않은 요청에 대한 에러 처리는 401 UNAUTHORIZED 처리
        ApiErrorResponse errorResponse = new ApiErrorResponse(HttpStatus.UNAUTHORIZED, "인가 받지 않은 요청입니다.");
        String jsonResponseData = mapper.writeValueAsString(errorResponse);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(jsonResponseData);
    }
}
