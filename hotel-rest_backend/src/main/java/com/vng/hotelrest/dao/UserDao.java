package com.vng.hotelrest.dao;


import com.vng.hotelrest.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDao extends JpaRepository<User, Long> {
   // @Query("select c from User c where c.username=:username")
    User findByUsername(String username);
}
