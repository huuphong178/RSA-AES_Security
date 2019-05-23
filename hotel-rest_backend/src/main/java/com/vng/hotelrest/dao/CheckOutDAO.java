package com.vng.hotelrest.dao;

import com.vng.hotelrest.entity.CheckOut;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CheckOutDAO extends JpaRepository<CheckOut, Long> {
}
