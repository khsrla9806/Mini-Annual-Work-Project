package com.mini.anuualwork.controller;

import com.mini.anuualwork.core.ApiDataResponse;
import com.mini.anuualwork.dto.AdminDto.*;
import com.mini.anuualwork.service.AdminService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api/admin")
@RestController
public class AdminController {

    private final AdminService adminService;

    @GetMapping("/user")
    public ApiDataResponse<List<RequestAllMembers>> allMemberList() {
        return this.adminService.getAllMembers();
    }

    @DeleteMapping("/user/{id}")
    public ApiDataResponse<ResponseSuccess> deleteMember(@PathVariable Long id) {
        return this.adminService.deleteMember(id);
    }

    @PostMapping("/work")
    public ApiDataResponse<ResponseSuccess> createWork(@RequestBody RequestCreateWork dto) {
        return this.adminService.createWork(dto);
    }

    @DeleteMapping("/work/{workId}")
    public ApiDataResponse<ResponseSuccess> deleteWork(@PathVariable Long workId) {
        return this.adminService.deleteWork(workId);
    }

    @GetMapping("/annual")
    public ApiDataResponse<List<ResponseAnnual>> annualList() {
        return this.adminService.getAnnualList();
    }
}
