package com.mini.anuualwork.controller.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mini.anuualwork.entity.Member;
import com.mini.anuualwork.entity.MemberRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class MemberDto {

    @Data
    @Builder
    public static class CreateRequest {
        @NotNull
        private String email;

        @NotNull
        private String name;

        @NotNull
        private String employeeNumber;

        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
        @NotNull
        @Size(min = 3, max = 100)
        private String password;
    }

    @AllArgsConstructor
    @Getter
    public static class CreateResponse {
        private String message;
    }

    @Data
    @Builder
    public static class LoginRequest {
        @NotNull
        private String email;

        @NotNull
        @Size(min = 3, max = 100)
        private String password;
    }

    @AllArgsConstructor
    @Getter
    public static class LoginResponse {
        private MemberInfo user;
        private String token;

        public static LoginResponse fromEntity(Member member, String token) {
            return new LoginResponse(MemberInfo.fromEntity(member), token);
        }


        @Getter
        @Builder
        static class MemberInfo {
            private String email;
            private String name;
            private String employeeNumber;
            private MemberRole role;

            public static MemberInfo fromEntity(Member member) {
                return MemberInfo.builder()
                        .email(member.getEmail())
                        .name(member.getName())
                        .employeeNumber(member.getEmployeeNumber())
                        .role(member.getMemberRole())
                        .build();
            }
        }
    }
}
