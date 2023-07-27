package com.mini.anuualwork.component.security;

import com.mini.anuualwork.entity.Member;
import com.mini.anuualwork.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(final String email) {
        Optional<Member> member = memberRepository.findByEmail(email);
        if (member.isEmpty()) {
            log.info("DB에 해당 이메일을 가진 사용자가 존재하지 않습니다.");
            return null;
        }

        return new CustomUserDetails(member.get());
    }
}
