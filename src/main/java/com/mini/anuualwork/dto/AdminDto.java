package com.mini.anuualwork.dto;

import com.mini.anuualwork.entity.Member;
import com.mini.anuualwork.entity.Work;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

import javax.validation.constraints.Future;
import javax.validation.constraints.NotNull;
import java.sql.Timestamp;

public class AdminDto {

    /* 집계 쿼리가 포함된 JPQL Projection 결과를 Converting 하기 위해서는 interface + Getter 사용 */
    public interface RequestAllMembers {
        Long getId();
        String getName();
        String getEmail();
        String getEmployeeNumber();
        Integer getRestAnnual();
        Integer getWorkDay();
    }

    @AllArgsConstructor
    @Getter
    public static class ResponseSuccess {
        private String message;
    }

    @Data
    public static class RequestCreateWork {
        @NotNull
        private Long id;

        @NotNull
        @Future
        private Timestamp date;

        public Work toEntity(Member member) {
            Work work = new Work();
            work.setMember(member);
            work.setDate(this.date.toLocalDateTime());

            return work;
        }
    }
}
