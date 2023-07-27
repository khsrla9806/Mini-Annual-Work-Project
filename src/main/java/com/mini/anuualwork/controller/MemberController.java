package com.mini.anuualwork.controller;

import com.mini.anuualwork.component.security.CustomUserDetails;
import com.mini.anuualwork.component.security.TokenProvider;
import com.mini.anuualwork.controller.dto.MemberDto;
import com.mini.anuualwork.core.ApiDataResponse;
import com.mini.anuualwork.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class MemberController {
    private final MemberService memberService;
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    @PostMapping("/login")
    public ApiDataResponse<MemberDto.LoginResponse> login(@Valid @RequestBody MemberDto.LoginRequest loginDto) {

        /* 시큐리티 검증을 위한 UsernamePasswordAuthenticationToken 객체 생성 */
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());

        /* 이때 CustomUserDetailService.loadUserByUsername() 실행하여 DB에 유저가 있는지 찾아보고, 있으면 Authentication 반환 */
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        /* Context Holder(Security Session) 안에 로그인한 유저의 Authentication 저장 */
        SecurityContextHolder.getContext().setAuthentication(authentication);

        /* Authentication 정보를 가지고 JWT 토큰을 생성 */
        String jwtToken = tokenProvider.createToken(authentication);

        /* 응답 DTO 생성 */
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        MemberDto.LoginResponse responseDto = MemberDto.LoginResponse.fromEntity(userDetails.getMember(), jwtToken);

        return new ApiDataResponse<>(responseDto, HttpStatus.OK);
    }

    @PostMapping("/signup")
    public ApiDataResponse<MemberDto.CreateResponse> signup(@Valid @RequestBody MemberDto.CreateRequest signUpDto) {
        return memberService.signup(signUpDto);
    }

    @PostMapping("/user/annual")
    public ApiDataResponse<String> personalAnnualList() {
        return new ApiDataResponse<>("개인 연차 조회", HttpStatus.OK);
    }
}
