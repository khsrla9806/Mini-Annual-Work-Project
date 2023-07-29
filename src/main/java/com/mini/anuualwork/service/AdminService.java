package com.mini.anuualwork.service;

import com.mini.anuualwork.core.ApiDataResponse;
import com.mini.anuualwork.dto.AdminDto.*;
import com.mini.anuualwork.entity.Member;
import com.mini.anuualwork.entity.Work;
import com.mini.anuualwork.repository.AdminAnnualRepository;
import com.mini.anuualwork.repository.AdminMemberRepository;
import com.mini.anuualwork.repository.AdminWorkRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@RequiredArgsConstructor
@Service
public class AdminService {
    private static final Long TOTAL_ANNUAL_COUNT = 15L;

    private final AdminMemberRepository memberRepository;
    private final AdminWorkRepository workRepository;
    private final AdminAnnualRepository annualRepository;

    public ApiDataResponse<List<RequestAllMembers>> getAllMembers() {
        List<RequestAllMembers> allMembers =
                memberRepository.getAllMembersWithAnnualCountAndWorkCount(TOTAL_ANNUAL_COUNT, getThisYear());

        return new ApiDataResponse<>(allMembers);
    }

    @Transactional
    public ApiDataResponse<ResponseSuccess> deleteMember(Long id) {
        Member member = memberRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("존재하지 않는 유저입니다."));

        annualRepository.deleteAllByMember(member);
        workRepository.deleteAllByMember(member);
        memberRepository.delete(member);

        return new ApiDataResponse<>(new ResponseSuccess("사원 계정이 정상적으로 삭제되었습니다."));
    }

    @Transactional
    public ApiDataResponse<ResponseSuccess> createWork(RequestCreateWork dto) {
        Member member = memberRepository.findById(dto.getId())
                .orElseThrow(() -> new RuntimeException("존재하지 않는 유저입니다."));

        Work work = dto.toEntity(member);
        workRepository.save(work);

        return new ApiDataResponse<>(new ResponseSuccess("당직등록에 성공했습니다."));
    }

    @Transactional
    public ApiDataResponse<ResponseSuccess> deleteWork(Long workId) {
        Work work = workRepository.findById(workId)
                .orElseThrow(() -> new RuntimeException("존재하지 않는 당직 정보입니다."));

        workRepository.delete(work);

        return new ApiDataResponse<>(new ResponseSuccess("당직이 삭제되었습니다."));
    }

    public ApiDataResponse<List<ResponseAnnual>> getAnnualList() {
        List<ResponseAnnual> allAnnuals = this.annualRepository.findAnnualsIsUnapprovedOrCanceled(getThisYear());

        return new ApiDataResponse<>(allAnnuals);
    }

    private int getThisYear() {
        return LocalDateTime.now().getYear();
    }
}
