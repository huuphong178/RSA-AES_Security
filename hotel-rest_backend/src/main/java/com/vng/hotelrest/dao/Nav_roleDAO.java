package com.vng.hotelrest.dao;

import com.vng.hotelrest.entity.nav_role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface Nav_roleDAO extends JpaRepository<nav_role, Long> {
    @Modifying
    @Query(value = "update nav_role r set r.roles=:roles where r.name=:name", nativeQuery = true)
    void saveRole(@Param("name") String name, @Param("roles") String roles);
}
