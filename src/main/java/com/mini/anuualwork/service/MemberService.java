package com.mini.anuualwork.service;

import com.mini.anuualwork.controller.dto.MemberDto;
import com.mini.anuualwork.core.ApiDataResponse;
import com.mini.anuualwork.entity.Member;
import com.mini.anuualwork.entity.MemberRole;
import com.mini.anuualwork.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public ApiDataResponse<MemberDto.CreateResponse> signup(MemberDto.CreateRequest signUpDto) {
        if (memberRepository.findByEmail(signUpDto.getEmail()).isPresent()) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        Member member = new Member();
        member.setEmail(signUpDto.getEmail());
        member.setName(signUpDto.getName());
        member.setEmployeeNumber(signUpDto.getEmployeeNumber());
        member.setPassword(passwordEncoder.encode(signUpDto.getPassword()));
        member.setMemberRole(MemberRole.ROLE_USER);
        memberRepository.save(member);

        return new ApiDataResponse<>(new MemberDto.CreateResponse("회원가입에 성공했습니다."), HttpStatus.CREATED);
    }
}
