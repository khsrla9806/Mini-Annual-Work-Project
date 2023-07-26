package com.mini.anuualwork.component.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider implements InitializingBean {

    private static final String AUTHORIZATION_KEY = "auth";
    private final String secret;
    private final long tokenValidityInMilliseconds;
    private Key key;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInMilliseconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInMilliseconds;
    }

    /* 빈 생성자 호출 후 실행 */
    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] decodedKeyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(decodedKeyBytes);
    }

    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // JWT 토큰 만료일 지정
        long now = new Date().getTime();
        Date validityDate = new Date(now + this.tokenValidityInMilliseconds);

        // 토큰을 만들어서 반환
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORIZATION_KEY, authorities) // JWT Payload 저장될 정보 "key(auth): value(authorities)"
                .signWith(key, SignatureAlgorithm.HS512) // 우리의 Secret key, 사용 알고리즘을 넣어 Sign 생성
                .setExpiration(validityDate)
                .compact();
    }

    /* Token -> Claims -> Authorities -> Principal 생성 -> Authentication 반환 */
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        String[] authoritiesArray = claims.get(AUTHORIZATION_KEY).toString().split(",");
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(authoritiesArray)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    /* 토큰 유효성 검사 */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다. : {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.info("만료된 토큰입니다. : {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 토큰입니다. : {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.info("잘못된 토큰입니다. : {}", e.getMessage());
        }

        return false;
    }
}
