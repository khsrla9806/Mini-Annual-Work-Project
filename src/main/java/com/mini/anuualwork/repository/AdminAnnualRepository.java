package com.mini.anuualwork.repository;

import com.mini.anuualwork.dto.AdminDto.*;
import com.mini.anuualwork.entity.Annual;
import com.mini.anuualwork.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface AdminAnnualRepository extends JpaRepository<Annual, Long> {

    void deleteAllByMember(Member member);

    @Query("SELECT " +
            "   a.id AS annualId, " +
            "   m.name AS name, " +
            "   m.employeeNumber AS employeeNumber, " +
            "   a.date AS date, " +
            "   a.status AS status " +
            "FROM Annual a " +
            "INNER JOIN Member m " +
            "ON a.member.id = m.id " +
            "WHERE YEAR(a.date) >= :thisYear AND a.status != 'APPROVED'")
    List<ResponseAnnual> findAnnualsIsUnapprovedOrCanceled(@Param("thisYear") Integer thisYear);
}
