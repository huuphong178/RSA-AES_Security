package com.vng.hotelrest.dao;

import com.vng.hotelrest.entity.Auth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthDAO extends JpaRepository<Auth, Long> {
    @Query(value = "select * from Auth where username=:username and password=:password", nativeQuery = true)
    Auth login(@Param("username") String username, @Param("password") String password);
    @Query("select c from Auth c where c.username=:username")
    Auth getOne(@Param("username") String username);
    @Modifying
    @Query("delete from Auth r where username=:username")
    void deletebyUsername(@Param("username") String username);
    @Modifying
    @Query(value = "update Auth r set r.role=:role where r.username=:username", nativeQuery = true)
    void saveRole(@Param("role") String role, @Param("username") String username);
}
